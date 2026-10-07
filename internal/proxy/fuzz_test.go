package proxy

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// Restored SSE output does not depend on how the network splits the stream,
// and a replacement standing as its own word never reaches the client.
func FuzzSSERestorationIgnoresChunkBoundaries(f *testing.F) {
	f.Add("hello ", " world", 7, true)
	f.Add("", "", 0, false)
	f.Add("{\"value\":\"", "\"}", 31, true)
	f.Add("x", "y", math.MinInt, true)
	r, fake := aliasPseudonym(f, "fuzz")
	f.Fuzz(func(t *testing.T, before, after string, split int, tool bool) {
		var stream string
		if tool {
			stream = anthropicToolDeltaEvent(before+" "+fake, 1) + anthropicToolDeltaEvent(" "+after, 1) +
				"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n"
		} else {
			stream = anthropicDeltaEvent(before+" "+fake[:len(fake)/2], 0) + anthropicDeltaEvent(fake[len(fake)/2:]+" "+after, 0) +
				"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
		}
		render := func(chunks ...string) (string, error) {
			var out bytes.Buffer
			writer := NewSSERestoringWriterForSession(&out, r, "fuzz")
			for _, chunk := range chunks {
				if _, err := writer.Write([]byte(chunk)); err != nil {
					return "", err
				}
			}
			err := writer.Close()
			return out.String(), err
		}
		whole, wholeErr := render(stream)
		// Take the remainder first: negating math.MinInt overflows.
		split %= len(stream) + 1
		if split < 0 {
			split += len(stream) + 1
		}
		parts, partsErr := render(stream[:split], stream[split:])
		if (wholeErr == nil) != (partsErr == nil) || whole != parts {
			t.Fatalf("split at %d changed output:\nwhole=%q %v\nparts=%q %v", split, whole, wholeErr, parts, partsErr)
		}
		if wholeErr == nil && strings.Contains(whole, fake) && !strings.Contains(before+after, fake) {
			t.Fatalf("replacement reached the client: %q", whole)
		}
	})
}
