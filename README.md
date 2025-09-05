# PassTek
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
<p align="center">
  <img src="img/logo_passtek.png" alt="PassTek logo" width="200"/>
</p>

**PassTek** is a Go program that analyzes password policy and provides various statistics about it.

## Features

- Passwords stats
  - Lengths
  - Complexity levels
  - Patterns
  - Occurrences
  - Password reuse
  - Usage of LanManager
  - Username as password 

- Visualize data with pie
- Export reports in multiple formats
- Templating and multi-language support

## Input Format

* Password file: one password per line
* Hash file: `username:rid:lmhash:nthash:::`


## Output Options

The program can output the results in different formats, including:

- Plain text (`.txt`): raw statistics and summaries
- Excel spreadsheet (`.xlsx`): organized sheets with stats and charts
- HTML report (`.html`): interactive visual charts (via ECharts)
- Screenshot (`.png`): screenshot of all pie charts
- PDF (`.pdf`): pdf version of the html report

## How to Use

To build:

```bash
git clone https://github.com/sysdream/PassTek.git
cd PassTek
go build cmd/PassTek.go
```

Command example:

```bash
./PassTek -p passwords.txt -H hashes.txt -L logo_sysdream.png -cL logo_client.png -o all -l en
```

## Options

```
  -H string
        Hash file (username:rid:lmhash:nthash:::)
  -L string
        Company logo file (png) (default "img/logo_sysdream.png")
  -anon
        Anonymize passwords (show first 2 and last 2 characters)
  -cL string
        Client logo file (png)
  -f string
        Output types (text, html, excel, screenshot, all) (default "all")
  -l string
        Output language (en,fr) (default "fr")
  -min int
        Minimum number of characters to be considered as an occurrence (default: 5) (default 5)
  -o string
        Output directory (default "output")
  -p string
        Password file (one per line)
  -top int
        Top N entries to display in charts and tables (default: 5) (default 5)
```

## TODO

* Refactor the codebase for better structure and maintainability
* Embed all static and template files for better portability

## License

This project is licensed under the [MIT License](LICENSE).

<div align="center">Made with 🍉 by leco</div>
