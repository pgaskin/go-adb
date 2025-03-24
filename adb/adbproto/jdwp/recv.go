// Copyright (C) 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jdwp

import (
	"bytes"
	"context"
	"io"
	"reflect"
)

// recv decodes all the incoming reply or command packets, forwarding them on
// to the corresponding chans. recv is blocking and should be run on a new
// go routine.
// recv returns when ctx is stopped or there's an IO error.
func (c *Connection) recv(ctx context.Context) {
	for ctx.Err() == nil {
		packet, err := c.readPacket()
		switch err {
		case nil:
		case io.EOF:
			return
		default:
			if ctx.Err() == nil {
				//fmt.Printf("Failed to read packet. Error: %v\n", err)
			}
			return
		}

		switch packet := packet.(type) {
		case replyPacket:
			c.Lock()
			out, ok := c.replies[packet.id]
			delete(c.replies, packet.id)
			c.Unlock()
			if !ok {
				//fmt.Printf("Unexpected reply for packet %d\n", packet.id)
				continue
			}
			out <- packet

		case cmdPacket:
			switch {
			case packet.cmdSet == cmdSetEvent && packet.cmdID == cmdCompositeEvent:
				d := ByteOrderReader(bytes.NewReader(packet.data), BigEndian)
				l := events{}
				if err := c.decode(d, reflect.ValueOf(&l)); err != nil {
					//fmt.Printf("Couldn't decode composite event data. Error: %v\n", err)
					continue
				}

				for _, ev := range l.Events {
					dbg("<%v> event: %T %+v", ev.request(), ev, ev)

					c.Lock()
					handler, ok := c.events[ev.request()]
					c.Unlock()

					if ok {
						handler <- ev
					} else {
						dbg("No event handler registered for %+v", ev)
					}
				}

			default:
				dbg("received unknown packet %+v", packet)
				// Unknown packet. Ignore.
			}
		}
	}
}
