package adapter

// ScriptQuestionType is the DNS question type a rule or dns script sees: the explicit
// ScriptQueryType of a legacy-mode lookup, otherwise the QueryType of the question.
func (c *InboundContext) ScriptQuestionType() uint16 {
	if c.ScriptQueryType != 0 {
		return c.ScriptQueryType
	}
	return c.QueryType
}
