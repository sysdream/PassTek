package export

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

func ToPDF(outputDir string) {
	var pdfBuf []byte

	// Get the current executable's directory
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("[!][ToPNG] Error getting executable path: %v", err)
	}
	exeDir := filepath.Dir(exePath)
	htmlFile := filepath.Join(exeDir, outputDir+"/report.html")
	outputPDF := filepath.Join(exeDir, outputDir+"/report.pdf")

	//htmlPath := "file://" + htmlFile

	// Create context
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	// Give time for rendering
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Run chromedp in about:blank page and inject HTML content (workarount error with chromerdp unknown IPAddressSpace value: Local)
	content, err := os.ReadFile(htmlFile)
	if err != nil {
		log.Fatalf("[!][ToPNG] Error reading HTML file: %v", err)
	}

	// Run chromedp tasks
	err = chromedp.Run(ctx, emulation.SetDeviceMetricsOverride(4000, 2000, 1.0, false).WithScreenOrientation(&emulation.ScreenOrientation{
		Type:  emulation.OrientationTypePortraitPrimary,
		Angle: 0,
	}),
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			lctx, cancel := context.WithCancel(ctx)
			defer cancel()
			var wg sync.WaitGroup
			wg.Add(1)

			chromedp.ListenTarget(lctx, func(ev interface{}) {
				if _, ok := ev.(*page.EventLoadEventFired); ok {
					cancel()
					wg.Done()
				}
			})

			frameTree, err := page.GetFrameTree().Do(lctx)
			if err != nil {
				return err
			}

			if err := page.SetDocumentContent(frameTree.Frame.ID, string(content)).Do(ctx); err != nil {
				return err
			}

			wg.Wait()
			return nil
		}),
		chromedp.Sleep(5*time.Second), // Wait for page load
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			pdfBuf, _, err = page.PrintToPDF().
				WithPrintBackground(true).
				WithPaperWidth(8.27).
				WithPaperHeight(11.69).
				Do(ctx)
			return err
		}),
	)
	if err != nil {
		log.Fatalf("[!][ToPDF] Failed to render PDF: %v", err)
	}

	// Write to PDF file
	if err := os.WriteFile(outputPDF, pdfBuf, 0644); err != nil {
		log.Fatalf("[!][ToPDF] Failed to write PDF file: %v", err)
	}
}
