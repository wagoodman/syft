package source

import "sort"

// LocationSet represents a set of string types.
type LocationSet map[Location]struct{}

// NewLocationSet creates a LocationSet populated with values from the given slice.
func NewLocationSet(start ...Location) LocationSet {
	ret := make(LocationSet)
	for _, s := range start {
		ret.Add(s)
	}
	return ret
}

// Add a string to the set.
func (s LocationSet) Add(i Location) {
	s[i] = struct{}{}
}

// Remove a string from the set.
func (s LocationSet) Remove(i Location) {
	delete(s, i)
}

// Contains indicates if the given string is contained within the set.
func (s LocationSet) Contains(i Location) bool {
	_, ok := s[i]
	return ok
}

// ToSlice returns a sorted slice of Locations that are contained within the set.
func (s LocationSet) ToSlice() []Location {
	ret := make([]Location, len(s))
	idx := 0
	for v := range s {
		ret[idx] = v
		idx++
	}
	sort.Sort(Locations(ret))
	return ret
}
