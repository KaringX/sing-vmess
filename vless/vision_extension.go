package vless

//https://github.com/starifly/sing-box

import (
	"bytes"
	"net"
	"reflect"
	"unsafe"

	"github.com/metacubex/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

type EncryptionConn interface {
	net.Conn
	IsEncryptionLayer() bool
}

type visionConnInfo struct {
	netConn  net.Conn
	rawConn  net.Conn
	input    *bytes.Reader
	rawInput *bytes.Buffer
}

func extractVisionConnInfo(conn net.Conn, baseConn net.Conn) (*visionConnInfo, error) {
	if isEncryptionConn(baseConn) {
		return extractEncryptionInfo(conn, baseConn)
	}

	encConn := findEncryptionInStack(conn)
	if encConn != nil {
		return extractTLSWithEncryptionInfo(baseConn, encConn)
	}

	return extractTLSInfo(baseConn)
}

func extractEncryptionInfo(conn net.Conn, encConn net.Conn) (*visionConnInfo, error) {
	info := &visionConnInfo{}

	if upstream, ok := encConn.(common.WithUpstream); ok {
		if upstreamConn, ok := upstream.Upstream().(net.Conn); ok {
			info.netConn = upstreamConn
			info.rawConn = upstreamConn
		}
	}

	if err := extractInputFields(encConn, info); err != nil {
		return nil, err
	}

	return info, nil
}

func extractTLSWithEncryptionInfo(tlsConn net.Conn, encConn net.Conn) (*visionConnInfo, error) {
	info := &visionConnInfo{}

	for _, tlsCreator := range tlsRegistry {
		loaded, netConn, _, _ := tlsCreator(tlsConn)
		if loaded {
			info.netConn = netConn
			break
		}
	}
	if info.netConn == nil {
		return nil, E.New("vision: not a valid supported TLS connection: ", reflect.TypeOf(tlsConn))
	}

	if isXorConn(encConn) {
		info.rawConn = encConn
		if err := extractInputFieldsFromTLS(tlsConn, info); err != nil {
			return nil, err
		}
	} else {
		if upstream, ok := encConn.(common.WithUpstream); ok {
			if upstreamConn, ok := upstream.Upstream().(net.Conn); ok {
				info.rawConn = upstreamConn
			}
		}
		if err := extractInputFields(encConn, info); err != nil {
			return nil, err
		}
	}

	return info, nil
}

func extractTLSInfo(tlsConn net.Conn) (*visionConnInfo, error) {
	info := &visionConnInfo{}

	for _, tlsCreator := range tlsRegistry {
		loaded, netConn, reflectType, reflectPointer := tlsCreator(tlsConn)
		if loaded {
			info.netConn = netConn
			info.rawConn = netConn

			inputField, _ := reflectType.FieldByName("input")
			rawInputField, _ := reflectType.FieldByName("rawInput")
			info.input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
			info.rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
			return info, nil
		}
	}

	return nil, E.New("vision: not a valid supported TLS connection: ", reflect.TypeOf(tlsConn))
}

func extractInputFields(encConn net.Conn, info *visionConnInfo) error {
	reflectType := reflect.TypeOf(encConn).Elem()
	reflectPointer := uintptr(unsafe.Pointer(reflect.ValueOf(encConn).Pointer()))

	inputField, inputOk := reflectType.FieldByName("input")
	rawInputField, rawInputOk := reflectType.FieldByName("rawInput")

	if !inputOk || !rawInputOk {
		return E.New("vision: encryption layer missing input/rawInput fields")
	}

	info.input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
	info.rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
	return nil
}

func extractInputFieldsFromTLS(tlsConn net.Conn, info *visionConnInfo) error {
	for _, tlsCreator := range tlsRegistry {
		loaded, _, reflectType, reflectPointer := tlsCreator(tlsConn)
		if loaded {
			inputField, _ := reflectType.FieldByName("input")
			rawInputField, _ := reflectType.FieldByName("rawInput")
			info.input = (*bytes.Reader)(unsafe.Pointer(reflectPointer + inputField.Offset))
			info.rawInput = (*bytes.Buffer)(unsafe.Pointer(reflectPointer + rawInputField.Offset))
			return nil
		}
	}
	return E.New("vision: failed to extract input fields from TLS connection")
}

func isEncryptionConn(conn net.Conn) bool {
	if enc, ok := conn.(EncryptionConn); ok {
		return enc.IsEncryptionLayer()
	}
	if reflect.TypeOf(conn).Kind() == reflect.Ptr {
		typeName := reflect.TypeOf(conn).Elem().Name()
		return typeName == "CommonConn" || typeName == "XorConn"
	}
	return false
}

func isXorConn(conn net.Conn) bool {
	if reflect.TypeOf(conn).Kind() == reflect.Ptr {
		return reflect.TypeOf(conn).Elem().Name() == "XorConn"
	}
	return false
}

func findEncryptionInStack(conn net.Conn) net.Conn {
	current := conn
	visited := make(map[uintptr]struct{})

	for current != nil {
		ptr := reflect.ValueOf(current).Pointer()
		if _, ok := visited[ptr]; ok {
			break
		}
		visited[ptr] = struct{}{}

		if isEncryptionConn(current) {
			return current
		}

		next := getNextConn(current)
		if next == nil || next == current {
			break
		}
		current = next
	}

	return nil
}

func getNextConn(conn net.Conn) net.Conn {
	connValue := reflect.ValueOf(conn)
	if connValue.Kind() == reflect.Ptr {
		connElem := connValue.Elem()
		if connElem.IsValid() && connElem.Kind() == reflect.Struct {
			if extField := connElem.FieldByName("ExtendedConn"); extField.IsValid() && !extField.IsNil() {
				extConn := extField.Interface()
				if upstream, ok := extConn.(common.WithUpstream); ok {
					if next, ok := upstream.Upstream().(net.Conn); ok && next != nil {
						return next
					}
				}
				if next, ok := extConn.(net.Conn); ok {
					return next
				}
			}

			if connField := connElem.FieldByName("Conn"); connField.IsValid() {
				if connField.Kind() == reflect.Interface && !connField.IsNil() {
					if next, ok := connField.Interface().(net.Conn); ok {
						return next
					}
				}
			}
		}
	}

	if upstream, ok := conn.(common.WithUpstream); ok {
		if next, ok := upstream.Upstream().(net.Conn); ok && next != nil {
			return next
		}
	}

	return nil
}

func (c *VisionConn) SetDirectConn(conn net.Conn) {
	if conn == nil {
		return
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	c.directConn = conn
	if c.directWrite {
		c.writer = bufio.NewVectorisedWriter(conn)
	}
}

func (c *VisionConn) SetUplinkConn(conn net.Conn) {
	c.SetDirectConn(conn)
}

type netConnProvider interface {
	NetConn() net.Conn
}

func unwrapConn(conn net.Conn) net.Conn {
	visited := make(map[net.Conn]struct{})
	for conn != nil {
		if _, ok := visited[conn]; ok {
			break
		}
		visited[conn] = struct{}{}

		// Check if this is a TLS connection by testing with TLS registry
		if isTLSConn(conn) {
			break
		}

		if isEncryptionConn(conn) {
			break
		}

		switched := false

		// Try common.WithUpstream first (most specific)
		if upstream, ok := conn.(common.WithUpstream); ok {
			if next, ok := upstream.Upstream().(net.Conn); ok && next != nil && next != conn {
				conn = next
				switched = true
				continue
			}
		}

		// Then try netConnProvider
		if provider, ok := conn.(netConnProvider); ok {
			next := provider.NetConn()
			if next != nil && next != conn {
				conn = next
				switched = true
				continue
			}
		}

		if reader, ok := conn.(N.WithUpstreamReader); ok {
			if replacer, ok := conn.(N.ReaderWithUpstream); ok && replacer.ReaderReplaceable() {
				if next, ok := reader.UpstreamReader().(net.Conn); ok && next != nil && next != conn {
					conn = next
					switched = true
					continue
				}
			}
		}
		if writer, ok := conn.(N.WithUpstreamWriter); ok {
			if replacer, ok := conn.(N.WriterWithUpstream); ok && replacer.WriterReplaceable() {
				if next, ok := writer.UpstreamWriter().(net.Conn); ok && next != nil && next != conn {
					conn = next
					switched = true
					continue
				}
			}
		}
		if !switched {
			break
		}
	}
	return conn
}

// isTLSConn checks if a connection can be recognized by the TLS registry
func isTLSConn(conn net.Conn) bool {
	for _, tlsCreator := range tlsRegistry {
		loaded, _, _, _ := tlsCreator(conn)
		if loaded {
			return true
		}
	}
	return false
}

func (c *VisionConn) ReaderReplaceable() bool {
	return c.directRead
}

func (c *VisionConn) WriterReplaceable() bool {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	return c.directWrite
}

func (c *VisionConn) UpstreamReader() any {
	if c.directRead {
		return c.directConn
	}
	return nil
}

func (c *VisionConn) UpstreamWriter() any {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.directWrite {
		return c.directConn
	}
	return nil
}

/*

func (c *VisionConn) Write(p []byte) (n int, err error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if c.numberOfPacketToFilter > 0 {
		c.filterTLS([][]byte{p})
	}
	if c.isPadding {
		inputLen := len(p)
		buffers := reshapeBuffer(p)
		isComplete := isCompleteRecord(p) //https://github.com/starifly/sing-box
		switchToDirectAfterWrite := false //https://github.com/starifly/sing-box
		//var specIndex int //https://github.com/starifly/sing-box
		for i, buffer := range buffers {
			if c.isTLS && buffer.Len() > 6 && bytes.Equal(tlsApplicationDataStart, buffer.To(3)) && isComplete { //https://github.com/starifly/sing-box
				//var command byte = commandPaddingEnd //https://github.com/starifly/sing-box
				if c.enableXTLS && c.canSplice {
					switchToDirectAfterWrite = true //https://github.com/starifly/sing-box
					//c.directWrite = true //https://github.com/starifly/sing-box
					//specIndex = i //https://github.com/starifly/sing-box
					//command = commandPaddingDirect //https://github.com/starifly/sing-box
				}
				c.isPadding = false
				if i == len(buffers)-1 { //https://github.com/starifly/sing-box
					var command byte = commandPaddingEnd
					if switchToDirectAfterWrite {
						command = commandPaddingDirect
					}
					buffers[i] = c.padding(buffer, command)
				} else { //https://github.com/starifly/sing-box
					buffers[i] = c.padding(buffer, commandPaddingContinue)
				}
				continue //https://github.com/starifly/sing-box
				//buffers[i] = c.padding(buffer, command)//https://github.com/starifly/sing-box
				//break//https://github.com/starifly/sing-box
			} else if !c.isTLS12orAbove && c.numberOfPacketToFilter <= 1 {
				c.isPadding = false
				buffers[i] = c.padding(buffer, commandPaddingEnd)
				break
			}
			var command byte = commandPaddingContinue //https://github.com/starifly/sing-box
			if i == len(buffers)-1 && !c.isPadding {  //https://github.com/starifly/sing-box
				command = commandPaddingEnd
				if switchToDirectAfterWrite {
					command = commandPaddingDirect
				}
			}
			buffers[i] = c.padding(buffer, command) //https://github.com/starifly/sing-box
		}
		//https://github.com/starifly/sing-box begin
		//if c.directWrite {
		//	encryptedBuffer := buffers[:specIndex+1]
		//	err = c.writer.WriteVectorised(encryptedBuffer)
		//	if err != nil {
		//		return
		//	}
		//	buffers = buffers[specIndex+1:]
		//	c.writer = bufio.NewVectorisedWriter(c.netConn)
		//	if len(buffers) > 0 {
		//		c.logger.Trace("XtlsWrite writeV ", specIndex, " ", buf.LenMulti(encryptedBuffer), " ", len(buffers))
		//		time.Sleep(5 * time.Millisecond) // wtf
		//	}
		//}
		//if len(buffers) > 0 {
		//	err = c.writer.WriteVectorised(buffers)
		//}
		//if err == nil {
		//	n = inputLen
		//}
		//https://github.com/starifly/sing-box end

		err = c.writer.WriteVectorised(buffers) //https://github.com/starifly/sing-box
		if err == nil {                         //https://github.com/starifly/sing-box
			n = inputLen
			if switchToDirectAfterWrite {
				c.directWrite = true
				c.writer = bufio.NewVectorisedWriter(c.directConn)
			}
		}

		return
	}
	if c.directWrite {
		return c.directConn.Write(p) //https://github.com/starifly/sing-box
	} else {
		return c.Conn.Write(p)
	}
}

*/
