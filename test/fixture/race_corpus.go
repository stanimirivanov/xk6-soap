package fixture

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

const RaceCorpusFile = "testdata/soap12/native-race-operations.json"
const RaceVUs = 16
const RaceIterations = 20

// RaceCorpus holds the literal operation XML for each validated exchange marker.
type RaceCorpus map[string]string

type raceOperation struct {
	XMLName xml.Name
	Marker  string     `xml:",chardata"`
	Nested  []struct{} `xml:",any"`
}

// ParseRaceCorpus validates the full per-VU workload in VU and iteration order.
func ParseRaceCorpus(data []byte) (RaceCorpus, error) {
	var entries []struct {
		Marker    string `json:"marker"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, errors.New("invalid race corpus JSON")
	}
	if len(entries) != RaceVUs*RaceIterations {
		return nil, fmt.Errorf("race corpus has %d entries, want %d", len(entries), RaceVUs*RaceIterations)
	}

	corpus := make(RaceCorpus, len(entries))
	for index, entry := range entries {
		expected := fmt.Sprintf("%d-%d", index/RaceIterations+1, index%RaceIterations)
		if entry.Marker != expected {
			return nil, fmt.Errorf("race corpus entry %d must have marker %s", index+1, expected)
		}
		if !validRaceOperation(entry.Operation, expected) {
			return nil, fmt.Errorf("race corpus entry %d has invalid Echo XML for marker %s", index+1, expected)
		}
		corpus[entry.Marker] = entry.Operation
	}
	return corpus, nil
}

func validRaceOperation(source, marker string) bool {
	decoder := xml.NewDecoder(strings.NewReader(source))
	token, err := decoder.Token()
	start, ok := token.(xml.StartElement)
	if err != nil || !ok {
		return false
	}
	var operation raceOperation
	if decoder.DecodeElement(&operation, &start) != nil || !operation.isEcho() || operation.Marker != marker {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}

func (operation raceOperation) isEcho() bool {
	return operation.XMLName == (xml.Name{Space: "urn:fixture:race", Local: "Echo"}) &&
		len(operation.Nested) == 0
}

var ErrRaceOperationMismatch = errors.New("race request operation differs from corpus")

// MatchRequest checks the original Body XML of a received request against the corpus.
// It returns a known marker on a byte mismatch so the receiver can tally it independently.
func (corpus RaceCorpus) MatchRequest(body []byte) (string, error) {
	var envelope struct {
		XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
		Bodies  []struct {
			Raw        string          `xml:",innerxml"`
			Operations []raceOperation `xml:",any"`
		} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
	}
	if xml.Unmarshal(body, &envelope) != nil || len(envelope.Bodies) != 1 || len(envelope.Bodies[0].Operations) != 1 {
		return "", errors.New("invalid race request envelope")
	}
	soapBody := envelope.Bodies[0]
	operation := soapBody.Operations[0]
	expected, ok := corpus[operation.Marker]
	if !operation.isEcho() || !ok {
		return "", errors.New("invalid race request Echo")
	}
	if soapBody.Raw != expected {
		return operation.Marker, ErrRaceOperationMismatch
	}
	return operation.Marker, nil
}
