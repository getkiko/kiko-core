package main

import (
	"context"
	"github.com/sagernet/sing-box/common/lifecycle"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/service"

	"github.com/spf13/cobra"
)

var commandRun = &cobra.Command{
	Use:   "run",
	Short: "Run service",
	Run: func(cmd *cobra.Command, args []string) {
		err := run()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	mainCommand.AddCommand(commandRun)
}

type OptionsEntry struct {
	content []byte
	path    string
	options option.Options
}

func readConfigAt(path string) (*OptionsEntry, error) {
	var (
		configContent []byte
		err           error
	)
	if path == "stdin" {
		configContent, err = io.ReadAll(os.Stdin)
	} else {
		configContent, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, E.Cause(err, "read config at ", path)
	}
	options, err := json.UnmarshalExtendedContext[option.Options](globalCtx, configContent)
	if err != nil {
		return nil, E.Cause(err, "decode config at ", path)
	}
	return &OptionsEntry{
		content: configContent,
		path:    path,
		options: options,
	}, nil
}

func readConfig() ([]*OptionsEntry, error) {
	var optionsList []*OptionsEntry
	for _, path := range configPaths {
		optionsEntry, err := readConfigAt(path)
		if err != nil {
			return nil, err
		}
		optionsList = append(optionsList, optionsEntry)
	}
	for _, directory := range configDirectories {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, E.Cause(err, "read config directory at ", directory)
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") || entry.IsDir() {
				continue
			}
			optionsEntry, err := readConfigAt(filepath.Join(directory, entry.Name()))
			if err != nil {
				return nil, err
			}
			optionsList = append(optionsList, optionsEntry)
		}
	}
	sort.Slice(optionsList, func(i, j int) bool {
		return optionsList[i].path < optionsList[j].path
	})
	return optionsList, nil
}

func readConfigAndMerge() (option.Options, error) {
	optionsList, err := readConfig()
	if err != nil {
		return option.Options{}, err
	}
	return mergeOptionsList(optionsList)
}

func mergeOptionsList(optionsList []*OptionsEntry) (option.Options, error) {
	if len(optionsList) == 1 {
		return optionsList[0].options, nil
	}
	var (
		mergedMessage json.RawMessage
		err           error
	)
	for _, options := range optionsList {
		mergedMessage, err = badjson.MergeJSON(globalCtx, options.options.RawMessage, mergedMessage, false)
		if err != nil {
			return option.Options{}, E.Cause(err, "merge config at ", options.path)
		}
	}
	var mergedOptions option.Options
	err = mergedOptions.UnmarshalJSONContext(globalCtx, mergedMessage)
	if err != nil {
		return option.Options{}, E.Cause(err, "unmarshal merged config")
	}
	return mergedOptions, nil
}

func create(options option.Options) (*box.Box, context.CancelFunc, error) {
	return createWithReloadError(options, "")
}

func createWithReloadError(options option.Options, reloadError string) (*box.Box, context.CancelFunc, error) {
	if disableColor {
		if options.Log == nil {
			options.Log = &option.LogOptions{}
		}
		options.Log.DisableColor = true
	}
	revision := ""
	for _, entry := range options.Services {
		if api, ok := entry.Options.(*option.APIServiceOptions); ok {
			revision = api.ConfigRevision
			if entry.Tag == "kiko-api" {
				break
			}
		}
	}
	state := lifecycle.New(revision, reloadError)
	ctx, cancel := context.WithCancel(service.ContextWith(service.ExtendContext(globalCtx), state))
	instance, err := box.New(box.Options{
		Context:                    ctx,
		Options:                    options,
		NetworkNamespaceHolderArgs: []string{"/proc/self/exe", commandNetnsHolder.Use},
	})
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "create service")
	}

	osSignals := make(chan os.Signal, 1)
	// run queues SIGHUP until startup completes. Only termination signals
	// cancel an in-progress start; the API may already be listening here.
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(osSignals)
		close(osSignals)
	}()
	startCtx, finishStart := context.WithCancel(context.Background())
	go func() {
		_, loaded := <-osSignals
		if loaded {
			cancel()
			closeMonitor(startCtx)
		}
	}()
	err = instance.Start()
	finishStart()
	if err != nil {
		cancel()
		return nil, nil, E.Cause(err, "start service")
	}
	state.Ready.Store(true)
	return instance, cancel, nil
}

func run() error {
	optionsList, err := readConfig()
	if err != nil {
		return err
	}
	options, err := mergeOptionsList(optionsList)
	if err != nil {
		return err
	}
	err = runInUserNamespaceIfNeeded(options, optionsList)
	if err != nil {
		return err
	}
	// Keep immutable snapshots: constructors and Start can mutate option values.
	snapshot, err := json.MarshalContext(globalCtx, options)
	if err != nil {
		return err
	}
	reloadSignals := make(chan os.Signal, 1)
	terminationSignals := make(chan os.Signal, 1)
	signal.Notify(reloadSignals, syscall.SIGHUP)
	signal.Notify(terminationSignals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(reloadSignals)
	defer signal.Stop(terminationSignals)
	instance, cancel, err := createSnapshot(snapshot, "")
	if err != nil {
		return err
	}
	for {
		// Separate queues preserve termination even when HUP is already pending.
		select {
		case <-terminationSignals:
			closeForExit(instance, cancel)
			return nil
		default:
		}
		select {
		case <-terminationSignals:
			closeForExit(instance, cancel)
			return nil
		case <-reloadSignals:
		}
		began := time.Now()
		next, readErr := readConfigAndMerge()
		if readErr != nil {
			log.Error(E.Cause(readErr, "reload: read configuration"))
			continue
		}
		candidate, encodeErr := json.MarshalContext(globalCtx, next)
		if encodeErr != nil {
			log.Error(E.Cause(encodeErr, "reload: snapshot configuration"))
			continue
		}
		// Check a separate decoded copy, then apply exactly the checked snapshot.
		checked, decodeErr := decodeSnapshot(candidate)
		if decodeErr != nil {
			log.Error(decodeErr)
			continue
		}
		if checkErr := checkOptions(checked); checkErr != nil {
			log.Error(E.Cause(checkErr, "reload: validate configuration"))
			continue
		}
		if liveSnapshot := instance.LiveSnapshot(); liveSnapshot != nil {
			// Restore the configuration applied live if the candidate fails.
			snapshot = liveSnapshot
		}
		log.Info("reload: closing previous instance")
		if closeErr := closeInstance(instance, cancel); closeErr != nil {
			// Continuing after incomplete cleanup can acquire the same resources twice.
			return E.Cause(closeErr, "reload: close previous instance")
		}
		// A pending termination wins over the new start and rollback.
		select {
		case <-terminationSignals:
			return nil
		default:
		}
		log.Info("reload: starting candidate instance")
		instance, cancel, err = createSnapshot(candidate, "")
		if err == nil {
			snapshot = candidate
			log.Info("reload: applied configuration in ", time.Since(began).Round(time.Millisecond))
			continue
		}
		reloadError := err.Error()
		log.Error(E.Cause(err, "reload: candidate failed; restoring previous configuration"))
		select {
		case <-terminationSignals:
			return nil
		default:
		}
		instance, cancel, err = createSnapshot(snapshot, reloadError)
		if err != nil {
			return E.Cause(err, "reload: restore previous configuration")
		}
		log.Warn("reload: previous configuration restored in ", time.Since(began).Round(time.Millisecond))
	}
}

func decodeSnapshot(snapshot []byte) (option.Options, error) {
	return json.UnmarshalExtendedContext[option.Options](globalCtx, snapshot)
}

func createSnapshot(snapshot []byte, reloadError string) (*box.Box, context.CancelFunc, error) {
	options, err := decodeSnapshot(snapshot)
	if err != nil {
		return nil, nil, err
	}
	return createWithReloadError(options, reloadError)
}

func closeInstance(instance *box.Box, cancel context.CancelFunc) error {
	ctx, closed := context.WithCancel(context.Background())
	defer closed()
	go closeMonitor(ctx)
	cancel()
	return instance.Close()
}

// exitCloseBudget bounds closing the instance when the process exits on
// a termination signal: the controller expects the core gone within a
// second. Whatever is still closing then goes with the process, as the
// kernel releases its sockets and TUN device and the cache file's
// database survives an exit mid-transaction.
const exitCloseBudget = 600 * time.Millisecond

// closeForExit closes the instance for a termination, waiting at most
// exitCloseBudget.
func closeForExit(instance *box.Box, cancel context.CancelFunc) {
	began := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		cancel()
		if err := instance.Close(); err != nil {
			log.Error(E.Cause(err, "close"))
		}
	}()
	select {
	case <-done:
		log.Info("sing-box closed in ", time.Since(began).Round(time.Millisecond))
	case <-time.After(exitCloseBudget):
		stack := make([]byte, 1<<20)
		size := runtime.Stack(stack, true)
		log.Warn("close exceeds ", exitCloseBudget, "; exiting. goroutines:\n", string(stack[:size]))
	}
}

func closeMonitor(ctx context.Context) {
	slow := time.NewTimer(2 * time.Second)
	defer slow.Stop()
	fatal := time.NewTimer(C.FatalStopTimeout)
	defer fatal.Stop()
	select {
	case <-ctx.Done():
		return
	case <-slow.C:
		stack := make([]byte, 1<<20)
		size := runtime.Stack(stack, true)
		log.Error("reload: close exceeds 2s; goroutines:\n", string(stack[:size]))
	}
	select {
	case <-ctx.Done():
		return
	case <-fatal.C:
		log.Fatal("sing-box did not close!")
	}
}
