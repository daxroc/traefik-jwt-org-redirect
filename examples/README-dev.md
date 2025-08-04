# Local Development Setup

This Docker Compose configuration has been refactored to use local source code instead of pulling from the git repository, enabling faster development and testing cycles.

## Changes Made

### Key Differences from Production Setup:
- **Local Plugin Loading**: Uses `--experimental.localPlugins` instead of `--experimental.plugins`
- **Source Code Mounting**: Mounts the parent directory (`../`) as the plugin source
- **File Provider**: Uses file-based configuration with watch enabled for dynamic updates
- **Development Configuration**: Includes debug logging and development-friendly settings

### File Structure:
```
jwt-org-redirect/
├── examples/
│   ├── docker-compose.yml          # Refactored for local development
│   ├── traefik-dynamic.yml         # Middleware configuration
│   ├── test-app/                   # Test application files
│   └── oauth-mock/                 # OAuth mock server
├── main.go                         # Plugin source code
├── go.mod                          # Go module definition
└── go.sum                          # Go dependencies
```

## Usage

1. **Start the development environment:**
   ```bash
   cd examples
   docker-compose up -d
   ```

2. **View logs for debugging:**
   ```bash
   docker-compose logs -f traefik
   ```

3. **Access services:**
   - Test application: http://localhost
   - Traefik dashboard: http://localhost:8080
   - OAuth mock server: http://localhost:3001

4. **Make changes to the plugin:**
   - Edit `../main.go` or other source files
   - Restart Traefik to reload the plugin:
     ```bash
     docker-compose restart traefik
     ```

5. **Update middleware configuration:**
   - Edit `traefik-dynamic.yml`
   - Changes are automatically reloaded (file watch enabled)

## Development Workflow

1. Make changes to the plugin source code in the parent directory
2. Restart the Traefik container to reload the plugin
3. Test your changes using the test application
4. Check logs for debugging information
5. Iterate quickly without needing to push to git

## Configuration Details

The `traefik-dynamic.yml` file contains the middleware configuration with:
- Debug logging enabled
- OAuth endpoint pointing to local mock server
- Development-friendly CORS settings
- Test session cookie configuration

## Troubleshooting

- **Plugin not loading**: Check that the source code is properly mounted at `/plugins/src/github.com/daxroc/traefik-jwt-org-redirect`
- **Configuration not updating**: Ensure file watch is enabled and the dynamic config file is properly mounted
- **OAuth flow issues**: Verify the oauth-mock server is running and accessible at localhost:3001
