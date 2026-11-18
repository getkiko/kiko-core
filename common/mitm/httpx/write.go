package httpx

import "bufio"

// WriteRequestHead writes the request line and header fields in order, followed by the empty line.
func WriteRequestHead(w *bufio.Writer, req *Request) error {
	w.WriteString(req.Method)
	w.WriteByte(' ')
	w.WriteString(req.Target)
	w.WriteByte(' ')
	w.WriteString(req.Proto)
	w.Write(crlf)
	return WriteHeader(w, req.Header)
}

// WriteResponseHead writes the status line and header fields in order, followed by the empty line.
func WriteResponseHead(w *bufio.Writer, resp *Response) error {
	w.WriteString(resp.Proto)
	code := resp.StatusCode
	if code < 100 || code > 999 {
		code = 502
	}
	w.WriteByte(' ')
	w.WriteByte(byte('0' + code/100))
	w.WriteByte(byte('0' + code/10%10))
	w.WriteByte(byte('0' + code%10))
	w.WriteByte(' ')
	w.WriteString(resp.Reason)
	w.Write(crlf)
	return WriteHeader(w, resp.Header)
}

// WriteHeader writes "Name: Value" lines in order and the terminating empty line.
func WriteHeader(w *bufio.Writer, h Header) error {
	for i := range h {
		w.WriteString(h[i].Name)
		w.WriteString(": ")
		w.WriteString(h[i].Value)
		w.Write(crlf)
	}
	_, err := w.Write(crlf)
	return err
}
