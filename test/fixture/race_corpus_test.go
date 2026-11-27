package fixture

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestRaceCorpus(t *testing.T) {
	data, err := os.ReadFile(RaceCorpusFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRaceCorpus(data); err != nil {
		t.Fatal(err)
	}
}

func TestRaceCorpusRejectsInvalidEntries(t *testing.T) {
	data, err := os.ReadFile(RaceCorpusFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]json.RawMessage) []json.RawMessage
	}{
		{"missing", func(entries []json.RawMessage) []json.RawMessage { return entries[1:] }},
		{"extra", func(entries []json.RawMessage) []json.RawMessage { return append(entries, entries[0]) }},
		{"unexpected marker", func(entries []json.RawMessage) []json.RawMessage {
			entries[0] = bytes.ReplaceAll(entries[0], []byte("1-0"), []byte("17-0"))
			return entries
		}},
		{"duplicate", func(entries []json.RawMessage) []json.RawMessage {
			entries[0] = entries[1]
			return entries
		}},
		{"wrong Echo namespace", func(entries []json.RawMessage) []json.RawMessage {
			entries[0] = bytes.ReplaceAll(entries[0], []byte("urn:fixture:race"), []byte("urn:fixture:other"))
			return entries
		}},
		{"valid operations swapped between markers", func(entries []json.RawMessage) []json.RawMessage {
			entries[0] = bytes.ReplaceAll(entries[0], []byte(">1-0<"), []byte(">1-1<"))
			entries[1] = bytes.ReplaceAll(entries[1], []byte(">1-1<"), []byte(">1-0<"))
			return entries
		}},
		{"multiple operations", func(entries []json.RawMessage) []json.RawMessage {
			entries[0] = bytes.ReplaceAll(entries[0], []byte("</m:Echo>"), []byte("</m:Echo><m:Echo/>"))
			return entries
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var entries []json.RawMessage
			if err := json.Unmarshal(data, &entries); err != nil {
				t.Fatal(err)
			}
			mutated, err := json.Marshal(tc.mutate(entries))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseRaceCorpus(mutated); err == nil {
				t.Fatal("accepted invalid race corpus")
			}
		})
	}
}

func TestRaceRequestOperationBytes(t *testing.T) {
	data, err := os.ReadFile(RaceCorpusFile)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := ParseRaceCorpus(data)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>`
	const suffix = `</s:Body></s:Envelope>`
	const operation = `<m:Echo xmlns:m="urn:fixture:race">1-0</m:Echo>`
	const byteMismatch = `<x:Echo xmlns:x="urn:fixture:race">1-0</x:Echo>`
	if marker, err := corpus.MatchRequest([]byte(prefix + operation + suffix)); err != nil || marker != "1-0" {
		t.Fatalf("exact Body operation rejected, error = %v", err)
	}
	if _, err := corpus.MatchRequest([]byte(prefix + byteMismatch + suffix)); !errors.Is(err, ErrRaceOperationMismatch) {
		t.Fatalf("Body with matching marker and different bytes returned %v", err)
	}
}
