package main

import (
	"image"
	"image/color"
	"image/png"
	"os"

	"github.com/jdxyw/generativeart"
	"github.com/jdxyw/generativeart/arts"
	"math/rand"
	"time"
)

func charToNum(char rune) int {
	if char >= '0' && char <= '9' {
		return int(char - '0')
	} else if char >= 'A' && char <= 'Z' {
		return int(char-'A') + 10
	} else {
		return 0
	}
}

func hashToColor(hash string, start int) color.RGBA {
	r := charToNum(rune(hash[start])) * 16
	g := charToNum(rune(hash[start+1])) * 16
	b := charToNum(rune(hash[start+2])) * 16
	return color.RGBA{uint8(r), uint8(g), uint8(b), 255}
}

func createImageFromHash(hash string) *image.RGBA {
	// Map hash values to art parameters
	background := hashToColor(hash, 3)                        // Background color
	lineWidth := float64(charToNum(rune(hash[9])))/10.0 + 0.1 // Line width

	// Define color scheme based on hash
	colors := []color.RGBA{
		hashToColor(hash, 10),
		hashToColor(hash, 13),
		hashToColor(hash, 16),
		hashToColor(hash, 19),
		hashToColor(hash, 22),
	}

	// Number of circles (used for the color canvas iterations)
	numCircles := charToNum(rune(hash[0]))*10 + 100

	c := generativeart.NewCanva(500, 500)
	c.SetBackground(background)
	c.SetLineWidth(lineWidth)
	c.FillBackground()
	c.SetColorSchema(colors)
	c.SetIterations(numCircles)

	c.Draw(arts.NewColorCanve(5))
	// Get the generated image
	genImg := c.Img()

	width, height := 500, 500
	newImg := image.NewRGBA(image.Rect(0, 0, width, height))

	// Define the circle's center and radius
	centerX, centerY, radius := width/2, height/2, 200

	// Copy only the part of genImg that falls within the circle onto newImg
	// Set the area outside the circle to be transparent
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if (x-centerX)*(x-centerX)+(y-centerY)*(y-centerY) <= radius*radius {
				newImg.Set(x, y, genImg.At(x, y))
			} else {
				newImg.Set(x, y, color.RGBA{0, 0, 0, 0}) // Fully transparent
			}
		}
	}
	return newImg
}

// createGridImage takes an array of hashes and arranges the resulting images in a grid
func createGridImage(hashes []string, gridWidth, gridHeight int) *image.RGBA {
	// Calculate individual image dimensions
	imgWidth, imgHeight := 500, 500 // Assuming each image is 500x500
	totalWidth := imgWidth * gridWidth
	totalHeight := imgHeight * gridHeight

	// Create a new image to hold the grid
	gridImg := image.NewRGBA(image.Rect(0, 0, totalWidth, totalHeight))

	// Generate and place each image in the grid
	for i, hash := range hashes {
		img := createImageFromHash(hash)

		// Calculate where to place the image in the grid
		x := (i % gridWidth) * imgWidth
		y := (i / gridWidth) * imgHeight

		// Draw the image onto the grid
		for py := 0; py < imgHeight; py++ {
			for px := 0; px < imgWidth; px++ {
				gridImg.Set(x+px, y+py, img.At(px, py))
			}
		}
	}

	return gridImg
}
func main() {
	rand.Seed(time.Now().Unix())
	hashes := []string{
		"5Uo157utEUjjvdfyrmPXg8GQsVfcMhadvfY6Gfj1tQmd",
		"87JeshQhXKBw36nULzpLpyn34Mhv1kGCccYyHU2BqGpT",
		"DD6YtMuCsWPyTAQR3YVVtyM78AYkEa4Vd3zKbcYG4qXV",
		"9JJxQSfRbePLRgznP3E5FgGTiBg7scQncCQy3R4q3LeQ",
		"4KbPXtkjvHv7G887cBpwES6WqPspE57t5J3rr2fuKMj6",
		"CFGwfAKHYFqMuxQhRG11jiW4duGyGj4yXDjFRXMMDoHV",
		"A6iuMASnCLGPVGgESWCiDfAWZZ8RiWQR5934JrJBDBoK",
		"CWGVDgwoo8yoSaBtV7ELS4Pg7bMd5Vvo9Xn7NrDqiF6n",
		"FHQRcu8u5pBSqt6wzAfe4ZTXaeFvhd6ZhpGdFoPw7sVE",
		"6UbY7Y5sWGRQeLsxp5YtK7hGFXExLfAscCbUzXdR25nJ",
		"6KUKHBN8gqAmVmWTMr2e3WoxqrfaRxWnhcssS5Um5rMb",
		"C9mh2sMv2EPUeK6ABgzxmWMXaH62zvW9mgXAagjF6PpH"}

	// Create a grid image from the hashes
	newImg := createGridImage(hashes, 4, 3) // 2x2 grid

	//newImg := createImageFromHash(hash)
	// Save the new image
	f, err := os.Create("circle_art.png")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	png.Encode(f, newImg)
}
