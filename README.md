# Code Analysis Platform

A web-based platform for analyzing Python code quality, security vulnerabilities, and running tests - all in your browser.

## Features

- **Code Quality Analysis**: Detects styling issues, syntax errors, and code smells using flake8
- **Security Scanning**: Identifies potential security vulnerabilities using Bandit security analyzer
- **Test Execution**: Run pytest unit tests and see results in real-time
- **Visual Reports**: Get clear, color-coded summaries with detailed breakdowns of all issues
- **Fast & Simple**: Just paste your code and click analyze - no installation required

## Use Cases

- **Code Review**: Quickly check code quality before committing
- **Learning**: Understand common Python pitfalls and security issues
- **Teaching**: Help students identify and fix code problems
- **Pre-commit Checks**: Validate code before pushing to production
- **Security Audits**: Scan for common security vulnerabilities (SQL injection, hardcoded passwords, etc.)

## What Gets Analyzed

- Code Quality
- Security
- Tests

## Tech Stack

**Frontend**: HTML, CSS, JavaScript  
**Backend**: FastAPI (Python)  
**Analysis Tools**: flake8, Bandit, pytest  
**Deployment**: Railway

## Notes

- This platform analyzes code but does not store it. All analysis happens in temporary files that are immediately deleted after processing.
- Deployment (Via Railway) must be active while running the website.

## Local Development

### Prerequisites
- Python 3.8+
- pip

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Code_analysis_platform.git
cd Code_analysis_platform
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Start the backend server:
```bash
uvicorn code_analyzer_api:app --reload
```

4. Open `htmlnocode.html` in your browser, or serve it using a local server:
```bash
python -m http.server 8000
```

5. Update the `API_URL` in `htmlnocode.html` to point to your local backend:
```javascript
const API_URL = 'http://localhost:8000';
```

## How to Use

1. Paste your Python code into the editor
2. (Optional) Add unit tests in pytest format
3. Click "Analyze Code"
4. Review the results:
   - **Code Quality**: See linting errors and warnings
   - **Security**: Check for vulnerabilities with severity ratings
   - **Tests**: View test results with pass/fail status



## Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## License

This project is open source and available under the MIT License.

## Author

Yatharth Agrawal

---

Made with care for cleaner, safer Python code
