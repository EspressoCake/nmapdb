package nmap

import (
	"encoding/xml"
	"strconv"
	"time"
)

type Timestamp time.Time

func (t *Timestamp) str2time(s string) error {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(ts, 0))
	return nil
}

func (t Timestamp) time2str() string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(t.time2str()), nil
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	return t.str2time(string(b))
}

func (t Timestamp) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: t.time2str()}, nil
}

func (t *Timestamp) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.str2time(attr.Value)
}

type NmapRun struct {
	Scanner          string         `xml:"scanner,attr" json:"scanner"`
	Args             string         `xml:"args,attr" json:"args"`
	Start            Timestamp      `xml:"start,attr" json:"start"`
	StartStr         string         `xml:"startstr,attr" json:"startstr"`
	Version          string         `xml:"version,attr" json:"version"`
	ProfileName      string         `xml:"profile_name,attr" json:"profile_name"`
	XMLOutputVersion string         `xml:"xmloutputversion,attr" json:"xmloutputversion"`
	ScanInfo         ScanInfo       `xml:"scaninfo" json:"scaninfo"`
	Verbose          Verbose        `xml:"verbose" json:"verbose"`
	Debugging        Debugging      `xml:"debugging" json:"debugging"`
	TaskBegin        []Task         `xml:"taskbegin" json:"taskbegin"`
	TaskProgress     []TaskProgress `xml:"taskprogress" json:"taskprogress"`
	TaskEnd          []Task         `xml:"taskend" json:"taskend"`
	PreScripts       []Script       `xml:"prescript>script" json:"prescripts"`
	PostScripts      []Script       `xml:"postscript>script" json:"postscripts"`
	Hosts            []Host         `xml:"host" json:"hosts"`
	Targets          []Target       `xml:"target" json:"targets"`
	RunStats         RunStats       `xml:"runstats" json:"runstats"`
}

type ScanInfo struct {
	Type        string `xml:"type,attr" json:"type"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	NumServices int    `xml:"numservices,attr" json:"numservices"`
	Services    string `xml:"services,attr" json:"services"`
	ScanFlags   string `xml:"scanflags,attr" json:"scanflags"`
}

type Verbose struct {
	Level int `xml:"level,attr" json:"level"`
}

type Debugging struct {
	Level int `xml:"level,attr" json:"level"`
}

type Task struct {
	Task      string    `xml:"task,attr" json:"task"`
	Time      Timestamp `xml:"time,attr" json:"time"`
	ExtraInfo string    `xml:"extrainfo,attr" json:"extrainfo"`
}

type TaskProgress struct {
	Task      string    `xml:"task,attr" json:"task"`
	Time      Timestamp `xml:"time,attr" json:"time"`
	Percent   float32   `xml:"percent,attr" json:"percent"`
	Remaining int       `xml:"remaining,attr" json:"remaining"`
	Etc       Timestamp `xml:"etc,attr" json:"etc"`
}

type Target struct {
	Specification string `xml:"specification,attr" json:"specification"`
	Status        string `xml:"status,attr" json:"status"`
	Reason        string `xml:"reason,attr" json:"reason"`
}

type Host struct {
	StartTime     Timestamp     `xml:"starttime,attr" json:"starttime"`
	EndTime       Timestamp     `xml:"endtime,attr" json:"endtime"`
	Comment       string        `xml:"comment,attr" json:"comment"`
	Status        Status        `xml:"status" json:"status"`
	Addresses     []Address     `xml:"address" json:"addresses"`
	Hostnames     []Hostname    `xml:"hostnames>hostname" json:"hostnames"`
	Smurfs        []Smurf       `xml:"smurf" json:"smurfs"`
	Ports         []Port        `xml:"ports>port" json:"ports"`
	ExtraPorts    []ExtraPorts  `xml:"ports>extraports" json:"extraports"`
	Os            Os            `xml:"os" json:"os"`
	Distance      Distance      `xml:"distance" json:"distance"`
	Uptime        Uptime        `xml:"uptime" json:"uptime"`
	TcpSequence   TcpSequence   `xml:"tcpsequence" json:"tcpsequence"`
	IpIdSequence  IpIdSequence  `xml:"ipidsequence" json:"ipidsequence"`
	TcpTsSequence TcpTsSequence `xml:"tcptssequence" json:"tcptssequence"`
	HostScripts   []Script      `xml:"hostscript>script" json:"hostscripts"`
	Trace         Trace         `xml:"trace" json:"trace"`
	Times         Times         `xml:"times" json:"times"`
}

type Status struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
}

type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addrtype"`
	Vendor   string `xml:"vendor,attr" json:"vendor"`
}

type Hostname struct {
	Name string `xml:"name,attr" json:"name"`
	Type string `xml:"type,attr" json:"type"`
}

type Smurf struct {
	Responses string `xml:"responses,attr" json:"responses"`
}

type ExtraPorts struct {
	State   string   `xml:"state,attr" json:"state"`
	Count   int      `xml:"count,attr" json:"count"`
	Reasons []Reason `xml:"extrareasons" json:"reasons"`
}

type Reason struct {
	Reason string `xml:"reason,attr" json:"reason"`
	Count  int    `xml:"count,attr" json:"count"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	PortId   int      `xml:"portid,attr" json:"id"`
	State    State    `xml:"state" json:"state"`
	Owner    Owner    `xml:"owner" json:"owner"`
	Service  Service  `xml:"service" json:"service"`
	Scripts  []Script `xml:"script" json:"scripts"`
}

type State struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
	ReasonIP  string  `xml:"reason_ip,attr" json:"reason_ip"`
}

type Owner struct {
	Name string `xml:"name,attr" json:"name"`
}

type Service struct {
	Name       string `xml:"name,attr" json:"name"`
	Conf       int    `xml:"conf,attr" json:"conf"`
	Method     string `xml:"method,attr" json:"method"`
	Version    string `xml:"version,attr" json:"version"`
	Product    string `xml:"product,attr" json:"product"`
	ExtraInfo  string `xml:"extrainfo,attr" json:"extrainfo"`
	Tunnel     string `xml:"tunnel,attr" json:"tunnel"`
	Proto      string `xml:"proto,attr" json:"proto"`
	Rpcnum     string `xml:"rpcnum,attr" json:"rpcnum"`
	Lowver     string `xml:"lowver,attr" json:"lowver"`
	Highver    string `xml:"hiver,attr" json:"hiver"`
	Hostname   string `xml:"hostname,attr" json:"hostname"`
	OsType     string `xml:"ostype,attr" json:"ostype"`
	DeviceType string `xml:"devicetype,attr" json:"devicetype"`
	ServiceFp  string `xml:"servicefp,attr" json:"servicefp"`
	CPEs       []CPE  `xml:"cpe" json:"cpes"`
}

type CPE string

type Script struct {
	Id       string    `xml:"id,attr" json:"id"`
	Output   string    `xml:"output,attr" json:"output"`
	Tables   []Table   `xml:"table" json:"tables"`
	Elements []Element `xml:"elem" json:"elements"`
}

type Table struct {
	Key      string    `xml:"key,attr" json:"key"`
	Elements []Element `xml:"elem" json:"elements"`
	Table    []Table   `xml:"table" json:"tables"`
}

type Element struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:",chardata" json:"value"`
}

type Os struct {
	PortsUsed      []PortUsed      `xml:"portused" json:"portsused"`
	OsMatches      []OsMatch       `xml:"osmatch" json:"osmatches"`
	OsFingerprints []OsFingerprint `xml:"osfingerprint" json:"osfingerprints"`
}

type PortUsed struct {
	State  string `xml:"state,attr" json:"state"`
	Proto  string `xml:"proto,attr" json:"proto"`
	PortId int    `xml:"portid,attr" json:"portid"`
}

type OsClass struct {
	Vendor   string `xml:"vendor,attr" json:"vendor"`
	OsGen    string `xml"osgen,attr"`
	Type     string `xml:"type,attr" json:"type"`
	Accuracy string `xml:"accurancy,attr" json:"accurancy"`
	OsFamily string `xml:"osfamily,attr" json:"osfamily"`
	CPEs     []CPE  `xml:"cpe" json:"cpes"`
}

type OsMatch struct {
	Name      string    `xml:"name,attr" json:"name"`
	Accuracy  string    `xml:"accuracy,attr" json:"accuracy"`
	Line      string    `xml:"line,attr" json:"line"`
	OsClasses []OsClass `xml:"osclass" json:"osclasses"`
}

type OsFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr" json:"fingerprint"`
}

type Distance struct {
	Value int `xml:"value,attr" json:"value"`
}

type Uptime struct {
	Seconds  int    `xml:"seconds,attr" json:"seconds"`
	Lastboot string `xml:"lastboot,attr" json:"lastboot"`
}

type TcpSequence struct {
	Index      int    `xml:"index,attr" json:"index"`
	Difficulty string `xml:"difficulty,attr" json:"difficulty"`
	Values     string `xml:"vaules,attr" json:"vaules"`
}

type Sequence struct {
	Class  string `xml:"class,attr" json:"class"`
	Values string `xml:"values,attr" json:"values"`
}

type IpIdSequence Sequence
type TcpTsSequence Sequence

type Trace struct {
	Proto string `xml:"proto,attr" json:"proto"`
	Port  int    `xml:"port,attr" json:"port"`
	Hops  []Hop  `xml:"hop" json:"hops"`
}

type Hop struct {
	TTL    float32 `xml:"ttl,attr" json:"ttl"`
	RTT    float32 `xml:"rtt,attr" json:"rtt"`
	IPAddr string  `xml:"ipaddr,attr" json:"ipaddr"`
	Host   string  `xml:"host,attr" json:"host"`
}

type Times struct {
	SRTT string `xml:"srtt,attr" json:"srtt"`
	RTT  string `xml:"rttvar,attr" json:"rttv"`
	To   string `xml:"to,attr" json:"to"`
}

type RunStats struct {
	Finished Finished  `xml:"finished" json:"finished"`
	Hosts    HostStats `xml:"hosts" json:"hosts"`
}

type Finished struct {
	Time     Timestamp `xml:"time,attr" json:"time"`
	TimeStr  string    `xml:"timestr,attr" json:"timestr"`
	Elapsed  float32   `xml:"elapsed,attr" json:"elapsed"`
	Summary  string    `xml:"summary,attr" json:"summary"`
	Exit     string    `xml:"exit,attr" json:"exit"`
	ErrorMsg string    `xml:"errormsg,attr" json:"errormsg"`
}

type HostStats struct {
	Up    int `xml:"up,attr" json:"up"`
	Down  int `xml:"down,attr" json:"down"`
	Total int `xml:"total,attr" json:"total"`
}

func Parse(content []byte) (*NmapRun, error) {
	r := &NmapRun{}
	err := xml.Unmarshal(content, r)
	return r, err
}
