package file

const (
	UnknownFileType Type = "unknownFileType"
	RegularFile     Type = "regularFile"
	HardLink        Type = "hardLink"
	SymbolicLink    Type = "symbolicLink"
	CharacterDevice Type = "characterDevice"
	BlockDevice     Type = "blockDevice"
	Directory       Type = "directory"
	FIFONode        Type = "fifoNode"
)

type Type string

func NewTypeFromTarHeaderTypeFlag(flag byte) Type {
	switch flag {
	case '0', '\x00':
		return RegularFile
	case '1':
		return HardLink
	case '2':
		return SymbolicLink
	case '3':
		return CharacterDevice
	case '4':
		return BlockDevice
	case '5':
		return Directory
	case '6':
		return FIFONode
	}
	return UnknownFileType
}
