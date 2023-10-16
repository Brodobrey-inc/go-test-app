package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Hub struct {
	addr          uint16
	name          string
	packet_number uint
	curr_time     uint64
	client        http.Client
	url           string
	sensors       map[string]*Sensor
	switches      map[string]*Switch
	devices       map[string]*DeviceUnit
	addrToName    map[uint16]string
	packetsToSend []Packet
}

type Sensor struct {
	props    env_sensor_props
	name     string
	temp     uint
	humidity uint
	light    uint
	polution uint
	addr     uint16
}

func (s *Sensor) updateValues(vals []uint) {
	pos := 0
	if s.props.sensors&0b1 != 0 {
		s.temp = vals[pos]
		pos++
	}
	if s.props.sensors&0b10 != 0 {
		s.humidity = vals[pos]
		pos++
	}
	if s.props.sensors&0b100 != 0 {
		s.light = vals[pos]
		pos++
	}
	if s.props.sensors&0b1000 != 0 {
		s.polution = vals[pos]
	}
}

type Switch struct {
	name       string
	devices    []string
	switchedOn byte
	addr       uint16
}

type DeviceUnit struct {
	name  string
	addr  uint16
	state byte
	dtype DeviceType
}

func (h *Hub) Start() {

	h.packet_number++
	packet := CreateWhoIsHerePacket(h.addr, h.packet_number)
	packets, err := packet.Request(h.client, h.url)
	if err != nil {
		os.Exit(99)
	}

	h.ProccessIncomingPackets(packets)

	for {
		packets, err := h.SendNextPacket()
		if err != nil {
			os.Exit(99)
		}
		h.ProccessIncomingPackets(packets)
	}
}

func (h *Hub) SendNextPacket() ([]Packet, error) {
	if len(h.packetsToSend) != 0 {
		packet := h.packetsToSend[0]
		h.packetsToSend = h.packetsToSend[1:]
		pack, err := packet.Request(h.client, h.url)
		if err.Error() == "error create request" {
			return []Packet{}, err
		}
		return pack, nil
	}
	resp, err := MakeRequest(h.client, h.url, nil)
	if err != nil {
		return []Packet{}, err
	}

	packets, err := DecodePackets(resp)
	if err != nil {
		return []Packet{}, err
	}

	return packets, nil
}

func (h *Hub) ProccessIncomingPackets(packets []Packet) {
	for _, packet := range packets {
		switch packet.payload.cmd {
		case WHOISHERE:
			h.ProccessHerePacket(packet, true)
		case IAMHERE:
			h.ProccessHerePacket(packet, false)
		case STATUS:
			h.ProccessStatusPacket(packet)
		case TICK:
			h.ProccessTickPacket(packet)
		}

	}

}

func (h *Hub) ProccessStatusPacket(packet Packet) {
	switch packet.payload.dev_type {
	case EnvSensorType:
		vals := ParseUintArrayFromBytes(packet.payload.cmd_body)
		sensor := h.sensors[h.addrToName[packet.payload.src]]
		sensor.updateValues(vals)
		h.EvaluateSensorAction(sensor)
	case SwitchType:
		sw := h.switches[h.addrToName[packet.payload.src]]
		sw.switchedOn = packet.payload.cmd_body[0]
	case LampType, SocketType:
		dev := h.devices[h.addrToName[packet.payload.src]]
		dev.state = packet.payload.cmd_body[0]
	default:
		return
	}
}

func (h *Hub) ProccessTickPacket(packet Packet) {
	time, _, _ := decode_uleb128(packet.payload.cmd_body, 0)
	h.curr_time = uint64(time)
}

func (h *Hub) ProccessHerePacket(packet Packet, needAnswer bool) {
	if needAnswer {
		h.packet_number++
		h.packetsToSend = append(h.packetsToSend, CreateIAmHerePacket(h.addr, h.packet_number))
		h.packet_number++
		h.packetsToSend = append(h.packetsToSend, CreateGetStatusPacket(h.addr, packet.payload.src, h.packet_number, packet.payload.dev_type))
	}
	device := DeviceFromBytes(packet.payload.cmd_body)
	h.addrToName[packet.payload.src] = device.dev_name

	switch packet.payload.dev_type {
	case EnvSensorType:
		var sensor Sensor
		sensor.addr = packet.payload.src
		sensor.name = device.dev_name
		sensor.props = SensorPropsFromBytes(device.dev_props)
		h.sensors[sensor.name] = &sensor
	case SwitchType:
		var sw Switch
		sw.addr = packet.payload.src
		sw.name = device.dev_name
		sw.devices = ParseStringArrayFromBytes(device.dev_props)
		h.switches[sw.name] = &sw
	case LampType, SocketType:
		var dev DeviceUnit
		dev.name = device.dev_name
		dev.addr = packet.payload.src
		dev.dtype = packet.payload.dev_type
		h.devices[dev.name] = &dev
	default:
		return
	}
}

func (h *Hub) EvaluateSensorAction(sensor *Sensor) {
	for _, trig := range sensor.props.triggers {
		if trig.op&0b01 == 0 {
			//smaller thep value
			switch trig.op & 0b0011 {
			case 0:
				h.EvaluateIfSmaller(trig.value, sensor.temp, trig.op&0b1, trig.name)
			case 1:
				h.EvaluateIfSmaller(trig.value, sensor.humidity, trig.op&0b1, trig.name)
			case 2:
				h.EvaluateIfSmaller(trig.value, sensor.light, trig.op&0b1, trig.name)
			case 3:
				h.EvaluateIfSmaller(trig.value, sensor.polution, trig.op&0b1, trig.name)
			}
		} else {
			//bigger then value
			switch trig.op & 0b0011 {
			case 0:
				h.EvaluateIfBigger(trig.value, sensor.temp, trig.op&0b1, trig.name)
			case 1:
				h.EvaluateIfBigger(trig.value, sensor.humidity, trig.op&0b1, trig.name)
			case 2:
				h.EvaluateIfBigger(trig.value, sensor.light, trig.op&0b1, trig.name)
			case 3:
				h.EvaluateIfBigger(trig.value, sensor.polution, trig.op&0b1, trig.name)
			}
		}
	}
}

func (h *Hub) EvaluateIfSmaller(thresh uint, value uint, status byte, name string) {
	dev := h.devices[name]
	if value < thresh && dev.state != status {
		h.packet_number++
		packet := CreateSetStatusPacket(h.addr, dev.addr, h.packet_number, dev.dtype, status)
		h.packetsToSend = append(h.packetsToSend, packet)
	}
}

func (h *Hub) EvaluateIfBigger(thresh uint, value uint, status byte, name string) {
	dev := h.devices[name]
	if value > thresh && dev.state != status {
		h.packet_number++
		packet := CreateSetStatusPacket(h.addr, dev.addr, h.packet_number, dev.dtype, status)
		h.packetsToSend = append(h.packetsToSend, packet)
	}
}

func InitHub(url string, addr uint16) *Hub {
	var hub Hub

	hub.url = url
	hub.addr = addr
	hub.name = DEV_NAME
	hub.client = http.Client{
		Timeout: 300 * time.Millisecond,
	}
	hub.packetsToSend = make([]Packet, 0)
	hub.addrToName = make(map[uint16]string)
	hub.addrToName = make(map[uint16]string)
	hub.sensors = make(map[string]*Sensor)
	hub.switches = make(map[string]*Switch)
	hub.devices = make(map[string]*DeviceUnit)

	return &hub
}

type DeviceType byte

const (
	SmartHubType DeviceType = iota + 1
	EnvSensorType
	SwitchType
	LampType
	SocketType
	ClockType
)

const DEV_NAME = "HUB01"

var PACKET_NUM = 0

type Command byte

const (
	WHOISHERE Command = iota + 1
	IAMHERE
	GETSTATUS
	STATUS
	SETSTATUS
	TICK
)

type Device struct {
	dev_name  string
	dev_props []byte
}

func (d Device) ToBytes() []byte {
	return append([]byte{byte(len(d.dev_name))}, append([]byte(d.dev_name), d.dev_props...)...)
}

func DeviceFromBytes(bytes []byte) Device {
	var dev Device

	dev.dev_name = string(bytes[1 : 1+bytes[0]])
	dev.dev_props = bytes[1+bytes[0]:]

	return dev
}

type Packet struct {
	length  byte
	payload Payload
	crc8    byte
}

type Payload struct {
	src      uint16
	dst      uint16
	serial   uint
	dev_type DeviceType
	cmd      Command
	cmd_body []byte
}

type env_sensor_props struct {
	sensors  byte
	triggers []trigger
}

type trigger struct {
	op    byte
	value uint
	name  string
}

func SensorPropsFromBytes(bytes []byte) env_sensor_props {
	var props env_sensor_props
	props.sensors = bytes[0]
	for i := 1; i < len(bytes); {
		var tr trigger
		tr.op = bytes[i]
		i++
		num, n, _ := decode_uleb128(bytes, i)
		i += n
		tr.value = uint(num)
		tr.name = string(bytes[i+1 : i+1+int(bytes[i])])
		i += 1 + int(bytes[i])
		props.triggers = append(props.triggers, tr)
	}
	return props
}

func (p Packet) EncodePacket() []byte {
	enc_packet := make([]byte, 1)
	payload_size := 0

	enc_int := encode_uleb128(uint(p.payload.src))
	payload_size += len(enc_int)
	enc_packet = append(enc_packet, enc_int...)

	enc_int = encode_uleb128(uint(p.payload.dst))
	payload_size += len(enc_int)
	enc_packet = append(enc_packet, enc_int...)

	enc_int = encode_uleb128(uint(p.payload.serial))
	payload_size += len(enc_int)
	enc_packet = append(enc_packet, enc_int...)

	enc_packet = append(enc_packet, byte(p.payload.dev_type))
	enc_packet = append(enc_packet, byte(p.payload.cmd))
	payload_size += 2

	enc_packet = append(enc_packet, p.payload.cmd_body...)
	payload_size += len(p.payload.cmd_body)

	enc_packet[0] = byte(payload_size)

	enc_packet = append(enc_packet, compute_crc8(enc_packet[1:]))

	len := base64.RawURLEncoding.EncodedLen(len(enc_packet))
	res_pack := make([]byte, len)
	base64.RawURLEncoding.Encode(res_pack, enc_packet)

	return res_pack
}

func DecodePacket(src []byte) (packet Packet, err error) {
	if len(src) < 7 {
		return Packet{}, errors.New("aaaaaa")
	}
	packet.length = src[0]
	packet.crc8 = src[len(src)-1]

	pos := 1
	parsed_int, n, err := decode_uleb128(src, pos)
	packet.payload.src = uint16(parsed_int)
	pos += n
	if err != nil {
		return Packet{}, errors.New("failed parse packet")
	}
	parsed_int, n, err = decode_uleb128(src, pos)
	packet.payload.dst = uint16(parsed_int)
	pos += n
	if err != nil {
		return Packet{}, errors.New("failed parse packet")
	}

	parsed_int, n, err = decode_uleb128(src, pos)
	packet.payload.serial = uint(parsed_int)
	pos += n
	if err != nil {
		return Packet{}, errors.New("failed parse packet")
	}

	packet.payload.dev_type = DeviceType(src[pos])
	pos += 1

	packet.payload.cmd = Command(src[pos])
	pos += 1

	packet.payload.cmd_body = src[pos : len(src)-1]

	return
}

func CreateWhoIsHerePacket(addr uint16, serial uint) (pack Packet) {
	pack.payload.src = addr
	pack.payload.dst = 0x3fff

	pack.payload.serial = serial

	pack.payload.dev_type = SmartHubType
	pack.payload.cmd = WHOISHERE

	device := Device{DEV_NAME, make([]byte, 0)}
	pack.payload.cmd_body = device.ToBytes()

	return
}

func CreateIAmHerePacket(addr uint16, serial uint) (pack Packet) {
	pack.payload.src = addr
	pack.payload.dst = 0x3fff

	pack.payload.serial = serial

	pack.payload.dev_type = SmartHubType
	pack.payload.cmd = IAMHERE

	device := Device{DEV_NAME, make([]byte, 0)}
	pack.payload.cmd_body = device.ToBytes()

	return
}

func CreateSetStatusPacket(src uint16, dst uint16, serial uint, dev_type DeviceType, status byte) (pack Packet) {
	pack.payload.src = src
	pack.payload.dst = dst

	pack.payload.serial = serial

	pack.payload.dev_type = dev_type
	pack.payload.cmd = SETSTATUS

	pack.payload.cmd_body = []byte{status}

	return
}

func CreateGetStatusPacket(src uint16, dst uint16, serial uint, dev_type DeviceType) (pack Packet) {
	pack.payload.src = src
	pack.payload.dst = dst

	pack.payload.serial = serial

	pack.payload.dev_type = dev_type
	pack.payload.cmd = GETSTATUS

	pack.payload.cmd_body = []byte{}

	return
}

func compute_crc8(bytes []byte) byte {
	var generator byte = 0x1D
	var crc byte = 0

	for _, currByte := range bytes {
		crc ^= currByte

		for i := 0; i < 8; i++ {
			if (crc & 0x80) != 0 {
				crc = (byte)((crc << 1) ^ generator)
			} else {
				crc <<= 1
			}
		}
	}

	return crc
}

func encode_uleb128(num uint) []byte {
	var out []byte
	val := num
	for {
		currentByte := byte(val & 0b01111111)
		val >>= 7
		if val != 0 {
			currentByte |= 0b10000000
		}
		out = append(out, currentByte)

		if val == 0 {
			return out
		}
	}
}

func decode_uleb128(src []byte, pos int) (res int64, n int, err error) {
	curr_pos := pos
	shift := byte(0)
	next_byte := src[curr_pos]
	for next_byte&0x80 != 0 {
		res += int64((next_byte & 0x7f)) << shift
		curr_pos += 1
		if curr_pos >= len(src) {
			return -1, 0, errors.New("failed to parse int")
		}
		next_byte = src[curr_pos]
		shift += 7
	}
	res += int64(next_byte) << shift
	n = curr_pos - pos + 1

	return
}

func (p Packet) Request(client http.Client, requestURL string) ([]Packet, error) {
	resp, err := MakeRequest(client, requestURL, bytes.NewReader(p.EncodePacket()))
	if err != nil {
		return []Packet{}, err
	}

	return DecodePackets(resp)
}

func MakeRequest(client http.Client, requestURL string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, requestURL, body)
	if err != nil {
		return []byte{}, errors.New("error create request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, errors.New("error make request")
	}
	if resp.StatusCode == http.StatusNoContent {
		os.Exit(0)
	}

	defer resp.Body.Close()

	res, err := io.ReadAll(resp.Body)

	if err != nil {
		return []byte{}, errors.New("error read body")
	}

	return res, nil
}

func DecodePackets(bytes []byte) ([]Packet, error) {
	var packets []Packet

	sDec, _ := base64.RawURLEncoding.DecodeString(string(bytes))
	for curr_len := 0; curr_len < len(sDec); curr_len += int(sDec[curr_len]) + 2 {
		recvPack, err := DecodePacket(sDec[curr_len : curr_len+int(sDec[curr_len])+2])
		if err != nil {
			continue
		}
		packets = append(packets, recvPack)
	}

	return packets, nil
}

func ParseStringArrayFromBytes(bytes []byte) []string {
	strings_arr := make([]string, 0)
	for pos := 1; pos < len(bytes); pos += 1 + int(bytes[pos]) {
		str := string(bytes[pos+1 : pos+1+int(bytes[pos])])
		strings_arr = append(strings_arr, str)
	}
	return strings_arr
}

func ParseUintArrayFromBytes(bytes []byte) []uint {
	num_arr := make([]uint, 0)
	for pos := 1; pos < len(bytes); {
		num, n, _ := decode_uleb128(bytes, pos)
		pos += n
		num_arr = append(num_arr, uint(num))
	}
	return num_arr
}

func main() {
	args := os.Args[1:]
	if len(args) < 2 {
		os.Exit(99)
	}

	// url := "http://localhost:9998"
	// addr := "ef0"
	url := args[0]
	addr := args[1]

	number_addr, _ := strconv.ParseInt(addr, 16, 16)

	hub := InitHub(url, uint16(number_addr))
	hub.Start()
}
