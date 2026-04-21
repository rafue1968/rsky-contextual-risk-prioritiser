# Rsky

A Proof of Concept (POC) for a vulnerability prioritization platform designed to help security teams assess and rank vulnerabilities based on risk factors such as severity, exploitability, and business impact. This project aims to streamline the process of deciding which vulnerabilities to address first in a software system.

## Features

- **Frontend (Next.js)**: A modern web interface for visualizing and interacting with vulnerability data.
- **Backend (FastAPI)**: A high-performance API for managing vulnerability findings, built with Python and FastAPI for fast development and automatic documentation.
- **Data Models**: Structured schemas for findings, including severity levels and prioritization logic.
- **Modular Architecture**: Separated concerns between web and API components for easier maintenance and scaling.

## Structure

- `apps/web/` → Frontend application built with Next.js
- `apps/api/` → Backend API built with FastAPI
  - `models/` → Database models for findings
  - `routes/` → API endpoints
  - `schemas/` → Pydantic schemas for validation

## Installation

### Prerequisites

- Node.js (for the web app)
- Python 3.8+ (for the API)
- Git

### Backend Setup (FastAPI)

1. Navigate to the API directory:
   ```
   cd apps/api
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the API server:
   ```
   uvicorn main:app --reload
   ```

The API will be available at `http://localhost:8000` with automatic documentation at `http://localhost:8000/docs`.

### Frontend Setup (Next.js)

1. Navigate to the web directory:
   ```
   cd apps/web
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Run the development server:
   ```
   npm run dev
   ```

The web app will be available at `http://localhost:3000`.

## Usage

1. Start both the backend and frontend servers as described above.
2. Access the web interface to view and prioritize vulnerabilities.
3. Use the API endpoints to integrate with external tools or scripts.

### API Endpoints

- `GET /findings` - Retrieve all vulnerability findings
- `POST /findings` - Create a new finding
- `GET /findings/{id}` - Get a specific finding
- `PUT /findings/{id}` - Update a finding
- `DELETE /findings/{id}` - Delete a finding

Refer to the API documentation at `/docs` for detailed schemas and examples.

## Development

- **Linting**: Run `npm run lint` in the web directory for JavaScript/TypeScript checks.
- **Testing**: Add unit tests for both frontend and backend components.
- **Database**: The API uses a simple in-memory or file-based storage; consider integrating a database like PostgreSQL for production.

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-name`.
3. Make your changes and commit: `git commit -m 'Add feature'`.
4. Push to the branch: `git push origin feature-name`.
5. Open a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions or feedback, please open an issue in the repository.

