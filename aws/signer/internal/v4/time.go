package v4

import "time"

type SigningTime struct {
	time.Time
	timeFormat      string
	shortTimeFormat string
}

func NewSigningTime(t time.Time) SigningTime {
	return SigningTime{
		Time: t,
	}
}

func (m *SigningTime) TimeFormat() string {
	return m.format(&m.timeFormat, TimeFormat)
}

func (m *SigningTime) ShortTimeFormat() string {
	return m.format(&m.shortTimeFormat, ShortTimeFormat)
}

func (m *SigningTime) format(target *string, format string) string {
	if len(*target) > 0 {
		return *target
	}
	v := m.Time.Format(format)
	*target = v
	return v
}
