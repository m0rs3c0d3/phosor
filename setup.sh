#!/bin/bash

# PHOSOR Setup Script
# Quick setup for development and testing

set -e

echo "================================"
echo "PHOSOR Setup Script"
echo "================================"
echo ""

# Check Python version
echo "[1/6] Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Found Python $python_version"

# Setup backend
echo ""
echo "[2/6] Setting up backend..."
cd backend

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo "Backend setup complete!"
cd ..

# Setup frontend
echo ""
echo "[3/6] Setting up frontend..."
cd frontend

if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
else
    echo "Dependencies already installed"
fi

echo "Frontend setup complete!"
cd ..

# Create test log directory
echo ""
echo "[4/6] Creating test log directory..."
mkdir -p /tmp/phosor-logs
echo "Created /tmp/phosor-logs"

# Create startup scripts
echo ""
echo "[5/6] Creating startup scripts..."

cat > start-backend.sh << 'EOF'
#!/bin/bash
cd backend
source venv/bin/activate
echo "Starting PHOSOR Backend on http://localhost:8000"
echo "API Documentation: http://localhost:8000/docs"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
EOF

cat > start-frontend.sh << 'EOF'
#!/bin/bash
cd frontend
echo "Starting PHOSOR Frontend on http://localhost:3000"
npm run dev
EOF

cat > test-events.sh << 'EOF'
#!/bin/bash
# Generate test log events

echo "Generating test events to /tmp/phosor-logs/test.log"

while true; do
    # Random event types
    events=(
        "INFO Application started successfully"
        "WARNING High memory usage detected: 85%"
        "ERROR Database connection timeout"
        "INFO User login: admin from 192.168.1.100"
        "CRITICAL Failed password for root from 203.0.113.42"
        "WARNING Firewall blocked connection from 198.51.100.23"
        "INFO Backup completed successfully"
        "ERROR Disk space low: 95% used"
    )
    
    random_event=${events[$RANDOM % ${#events[@]}]}
    echo "$(date -Iseconds) $random_event" >> /tmp/phosor-logs/test.log
    
    echo "Generated: $random_event"
    sleep 2
done
EOF

chmod +x start-backend.sh start-frontend.sh test-events.sh

echo "Created startup scripts!"

# Print instructions
echo ""
echo "[6/6] Setup Complete!"
echo ""
echo "================================"
echo "Quick Start:"
echo "================================"
echo ""
echo "1. Start Backend:"
echo "   ./start-backend.sh"
echo ""
echo "2. Start Frontend (in new terminal):"
echo "   ./start-frontend.sh"
echo ""
echo "3. Access Dashboard:"
echo "   http://localhost:3000"
echo "   Login: admin / secret"
echo ""
echo "4. Generate Test Events (optional):"
echo "   ./test-events.sh"
echo ""
echo "================================"
echo "Testing Syslog:"
echo "================================"
echo ""
echo "Send test syslog message:"
echo "  echo '<38>Feb 03 12:00:00 host sshd: Failed password for user' | nc -u localhost 5140"
echo ""
echo "================================"
echo "Next Steps:"
echo "================================"
echo ""
echo "1. Add log file to monitor:"
echo "   - Start backend and frontend"
echo "   - Login to dashboard"
echo "   - API call to add /tmp/phosor-logs/test.log"
echo ""
echo "2. Create custom rules in the dashboard"
echo ""
echo "3. Read README.md for detailed documentation"
echo ""
