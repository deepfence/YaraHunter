package scan

import (
	"database/sql"
	"strings"

	"github.com/minio/highwayhash"
)

func GetHashFrom(data string) int {
	// use file path and modification time to generate the hash
	key := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
	}
	hash := highwayhash.Sum64([]byte(data), key)
	return int(hash)
}

func ExecuteBatch(db *sql.DB, batch []string, batchArgs []interface{}, tableName string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT OR REPLACE INTO "+tableName+"(hash, path) VALUES "+strings.Join(batch, ", "), batchArgs...)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func FindDeltaOfFiles(table1, table2 string, db *sql.DB, deletionOnly bool) (result map[int]string, err error) {
	rows, err := db.Query(`
		SELECT fmq.hash, fmq.path FROM ` + table1 + ` fmq
		LEFT JOIN ` + table2 + ` fm
		ON fmq.hash = fm.hash
		WHERE fm.hash IS NULL
	`)

	// for deletionOnly, filter out the rows of table1 whose path is not in table2
	if deletionOnly {
		rows, err = db.Query(`
		SELECT fm.hash, fm.path
		FROM ` + table1 + ` fm
		LEFT JOIN ` + table2 + ` fmq ON fm.path = fmq.path
		WHERE fmq.path IS NULL
		AND NOT EXISTS (
			SELECT 1
			FROM ` + table2 + ` fmq2
			WHERE fmq2.path = fm.path
		);
		`)
	}
	if err != nil {
		return result, err
	}
	defer rows.Close()

	result = make(map[int]string)
	for rows.Next() {
		var hash int
		var path string
		err = rows.Scan(&hash, &path)
		if err != nil {
			return result, err
		}
		result[hash] = path
	}

	return result, nil
}
