package wssec

import (
	"slices"
	"strconv"

	"github.com/knroy/go-xml/v2/xdm"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

const maxEncryptedParts = 16

func headerBlocks(doc *xmlsec.Document, ns string) []*xdm.Node {
	header := element(doc.Root()).FirstElement(ns, "Header")
	if header == nil {
		return nil
	}
	return header.ChildElements()
}

// A provider replacement preserves the slot of the direct header block.
func selectEncryptedHeaders(doc *xmlsec.Document, ns string, names []string, selectors []message.HeaderSelector) ([]int, error) {
	var slots []int
	seen := map[int]bool{}
	if len(names) == 0 || len(names) > maxEncryptedParts {
		return nil, ErrEncryptionBuild
	}
	blocks := headerBlocks(doc, ns)
	for _, name := range names {
		var selector *message.HeaderSelector
		for i := range selectors {
			if selectors[i].Name == name {
				if selector != nil {
					return nil, ErrEncryptionBuild
				}
				selector = &selectors[i]
			}
		}
		if selector == nil {
			return nil, ErrEncryptionBuild
		}
		slot := uniqueHeader(blocks, selector.Namespace, selector.LocalName)
		if slot < 0 || seen[slot] {
			return nil, ErrEncryptionBuild
		}
		seen[slot] = true
		slots = append(slots, slot)
	}
	return slots, nil
}

func encryptionDataID(index int) string { return "ed-" + strconv.Itoa(index+1) }

func uniqueHeader(blocks []*xdm.Node, namespace, local string) int {
	slot := -1
	for i, block := range blocks {
		if block.IsElement(namespace, local) && !block.IsElement(xmlsec.NSWSSE, "Security") {
			if slot != -1 {
				return -1
			}
			slot = i
		}
	}
	return slot
}

// Each provider replacement consumes one wrapper and yields one direct block
// in that slot. A decrypted name must never be ambiguous with a clear sibling.
func validRecoveredHeaders(blocks []*xdm.Node, graph responseEncryption, policy ReceivePolicy) bool {
	for _, slot := range graph.headerSlots {
		if slot >= len(blocks) {
			return false
		}
		n := blocks[slot].Name()
		switch n.URI {
		case "", xmlsec.NSSOAP11, xmlsec.NSSOAP12, xmlsec.NSWSSE, xmlsec.NSWSSE11, xmlsec.NSWSU, xmlsec.NSDSig:
			return false
		}
		if uniqueHeader(blocks, n.URI, n.Local) != slot {
			return false
		}
		for child := range blocks[slot].Descendants() {
			if child.Kind() == xdm.KindElement {
				switch child.Name().URI {
				case xmlsec.NSSOAP11, xmlsec.NSSOAP12, xmlsec.NSWSSE, xmlsec.NSWSSE11, xmlsec.NSWSU, xmlsec.NSDSig:
					return false
				}
			}
		}
	}
	for _, name := range policy.EncryptedHeaders {
		if !slices.Contains(graph.headerSlots, uniqueHeader(blocks, name.Namespace, name.LocalName)) {
			return false
		}
	}
	return true
}
