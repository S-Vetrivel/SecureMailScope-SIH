package main
import (
	"fmt"
	"strings"
)
func main() {
	line := "1|12345|1.1.1.1|2.2.2.2|TCP|60"
	parts := strings.SplitN(line, "|", 7)
	fmt.Println(len(parts))
	if len(parts) >= 6 {
		fmt.Println(parts[5])
		fmt.Println(parts[6]) // Panics here
	}
}
