package task

const (
	PackagesProduct Product = iota
	FileMetadataProduct
	FileDigestsProduct
	FileClassificationsProduct
	FileContentsProduct
	SecretsProduct
)

var AllProducts = []Product{
	PackagesProduct,
	FileMetadataProduct,
	FileDigestsProduct,
	FileClassificationsProduct,
	FileContentsProduct,
	SecretsProduct,
}

type Product int
