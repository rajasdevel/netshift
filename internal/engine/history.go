package engine

import (
	"errors"

	"github.com/rajasdevel/netshift/internal/store"
)

// record stamps r with the time and identity and appends it to the profile's
// history. Previews (Apply false) record nothing.
func (e *Engine) record(r store.HistoryRecord) error {
	if !e.Apply {
		return nil
	}
	r.At = e.now()
	if r.Identity == "" {
		r.Identity = e.Config.Identity
	}
	if e.History != nil {
		return e.History(r)
	}
	if e.StatePath == "" {
		return errors.New("history requires a state path")
	}
	return store.AppendHistory(store.HistoryPath(e.StatePath), r)
}
