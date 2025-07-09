# TEE Explorer - Dooor

A modern Next.js application for validating Google Cloud TEE (Trusted Execution Environment) attestation tokens and running transparent code audits.

## Features

- **Live TEE Validation**: Connect to your TEE server and validate attestation tokens in real-time
- **Manual JWT Validation**: Paste and validate JWT tokens manually
- **Transparent Code Auditor**: Execute cryptographically-proven code audits on TEE servers
- **Security Configuration Validation**: Check firewall settings and security configurations
- **Modern UI**: Built with shadcn/ui components and Tailwind CSS
- **Responsive Design**: Works on desktop and mobile devices

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd tee-explorer
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

4. Open [http://localhost:3000](http://localhost:3000) in your browser

## Usage

### Live TEE Validation

1. Enter your TEE server URL in the "TEE Server URL" field
2. Click one of the validation buttons:
   - **Connect & Validate TEE**: Full connection and validation
   - **Quick Validation**: Fast validation check
   - **Detailed Report**: Complete validation report
   - **Security Check**: Security configuration validation
   - **Complete Validation**: Full TEE + security validation

### Manual JWT Validation

1. Switch to the "Manual JWT Validation" tab
2. Paste your JWT token in the text field
3. Click "Validate JWT" to validate or "Decode Only" to just decode

### Transparent Code Auditor

1. Switch to the "Transparent Code Auditor" tab
2. Use the available buttons to:
   - **Check Health**: Verify auditor service health
   - **Run Audit**: Execute a transparent code audit
   - **Get Results**: Retrieve audit results
   - **Execution Log**: View execution trace
   - **Verification Info**: Get verification details

## Configuration

### Environment Variables

The application uses the following default configuration:

- **Project ID**: `dooor-core`
- **Zone**: `us-central1-a`
- **Instance Name**: `tee-vm1`
- **Default TEE URL**: `https://api-tee.dooor.ai/v1`

### Customization

The application uses Tailwind CSS with custom theme variables defined in:
- `tailwind.config.ts`: Custom colors, fonts, and animations
- `src/app/globals.css`: CSS custom properties and theme variables

#### Custom Colors

```css
/* TEE status colors */
--tee-success: #22c55e;
--tee-warning: #f59e0b;
--tee-error: #ef4444;
--tee-info: #3b82f6;

/* Security levels */
--security-high: #22c55e;
--security-medium: #f59e0b;
--security-low: #ef4444;
--security-critical: #dc2626;
```

## Architecture

### Components

- **TEEExplorer**: Main application component
- **StatusCard**: Displays validation results and status
- **UI Components**: shadcn/ui components for consistent styling

### Libraries

- **TEEAttestationValidator**: Handles TEE validation logic
- **TEEAuditorClient**: Manages auditor API communication
- **Utils**: Helper functions for formatting and validation

### API Integration

The application integrates with TEE servers through REST APIs:

- `/v1/tee/connect`: Connect and get attestation token
- `/v1/tee/auditor/health`: Check auditor health
- `/v1/tee/auditor/run`: Run transparent audit
- `/v1/tee/auditor/results`: Get audit results
- `/v1/tee/auditor/execution-log`: Get execution log
- `/v1/tee/auditor/verification`: Get verification info

## Development

### Project Structure

```
tee-explorer/
├── src/
│   ├── app/
│   │   ├── globals.css
│   │   ├── layout.tsx
│   │   └── page.tsx
│   ├── components/
│   │   ├── ui/
│   │   │   ├── button.tsx
│   │   │   ├── card.tsx
│   │   │   ├── input.tsx
│   │   │   ├── label.tsx
│   │   │   ├── tabs.tsx
│   │   │   ├── badge.tsx
│   │   │   ├── separator.tsx
│   │   │   └── status-card.tsx
│   │   └── tee-explorer.tsx
│   └── lib/
│       ├── utils.ts
│       ├── types.ts
│       └── tee-api.ts
├── public/
│   ├── logo.png
│   └── icon.ico
├── tailwind.config.ts
└── package.json
```

### Scripts

- `npm run dev`: Start development server
- `npm run build`: Build for production
- `npm run start`: Start production server
- `npm run lint`: Run ESLint

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is part of the Dooor platform.

## Support

For support and questions, please contact the Dooor team.
