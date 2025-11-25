import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Lock, 
  Unlock, 
  FileText, 
  Upload, 
  AlertTriangle, 
  User, 
  Key, 
  Share2, 
  Trash2, 
  Eye, 
  Activity, 
  CheckCircle, 
  XCircle, 
  Menu,
  Terminal,
  Search,
  HardDrive,
  Mail,
  Plus,
  Minus,
  Maximize
} from 'lucide-react';

// --- Mock Data & Utilities ---

const INITIAL_FILES = [
  { id: 1, name: 'Project_Alpha_Specs.pdf', size: '2.4 MB', type: 'pdf', owner: 'admin', encrypted: true, content: 'Confidential specifications for Project Alpha...' },
  { id: 2, name: 'Q3_Financials.xlsx', size: '1.1 MB', type: 'xlsx', owner: 'finance', encrypted: true, content: 'Revenue stream data...' },
  { id: 3, name: 'Employee_List.txt', size: '14 KB', type: 'txt', owner: 'hr', encrypted: false, content: 'John Doe, Jane Smith...' },
  { id: 4, name: 'System_Config.json', size: '4 KB', type: 'json', owner: 'admin', encrypted: false, content: '{ "version": "1.0.4" }' },
];

const generateId = () => Math.floor(Math.random() * 100000);

const getCurrentTime = () => new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

// --- Main Component ---

export default function SecureFileSystem() {
  // User Database (Simulated Backend)
  const [registeredUsers, setRegisteredUsers] = useState([
    { username: 'admin', password: 'password', email: 'admin@securefile.io' }
  ]);

  // Auth State
  const [authStep, setAuthStep] = useState('login'); // login, 2fa, signup, dashboard
  const [currentUser, setCurrentUser] = useState(null);
  
  // Inputs
  const [usernameInput, setUsernameInput] = useState('admin');
  const [passwordInput, setPasswordInput] = useState('');
  const [emailInput, setEmailInput] = useState('');
  const [confirmPasswordInput, setConfirmPasswordInput] = useState('');
  const [otpInput, setOtpInput] = useState('');
  
  // Process State
  const [authError, setAuthError] = useState('');
  const [signupStep, setSignupStep] = useState('details'); // 'details' | 'otp'
  const [isSimulatingEmail, setIsSimulatingEmail] = useState(false);
  const [otpSent, setOtpSent] = useState(false); // Used for Login 2FA
  const [zoomLevel, setZoomLevel] = useState(100); // New state for Zoom

  // App State
  const [files, setFiles] = useState(INITIAL_FILES);
  const [logs, setLogs] = useState([{ time: getCurrentTime(), type: 'info', message: 'System initialized. WAF Active.' }]);
  const [activeTab, setActiveTab] = useState('files');
  const [modal, setModal] = useState(null);

  // --- Security Logic & Helpers ---

  const addLog = (type, message) => {
    setLogs(prev => [{ time: getCurrentTime(), type, message }, ...prev]);
  };

  const resetInputs = () => {
    setPasswordInput('');
    setConfirmPasswordInput('');
    setOtpInput('');
    setAuthError('');
    setEmailInput('');
  };

  // --- Login Logic ---

  const handleLogin = (e) => {
    e.preventDefault();
    
    // 1. Validate Credentials against "Database"
    const foundUser = registeredUsers.find(u => u.username === usernameInput);

    if (!foundUser) {
      setAuthError('User not registered.');
      addLog('error', `Login failed: Unknown user '${usernameInput}'`);
      return;
    }

    if (foundUser.password !== passwordInput) {
      setAuthError('Invalid credentials.');
      addLog('warning', `Failed login attempt for user: ${usernameInput}`);
      return;
    }

    // 2. Proceed to 2FA
    setAuthStep('2fa');
    setAuthError('');
    setOtpSent(false);
    addLog('info', `Credentials verified for ${usernameInput}. Requesting 2FA.`);
  };

  const handleSendLoginOTP = () => {
    setIsSimulatingEmail(true);
    setAuthError('');
    
    const userEmail = registeredUsers.find(u => u.username === usernameInput)?.email || 'user@email.com';

    setTimeout(() => {
      setIsSimulatingEmail(false);
      setOtpSent(true);
      addLog('info', `2FA OTP Code sent to ${userEmail}`);
    }, 1500);
  };

  const handleVerifyLogin2FA = (e) => {
    e.preventDefault();
    if (otpInput === '123456') {
      setCurrentUser({ name: usernameInput, role: usernameInput === 'admin' ? 'admin' : 'user' });
      setAuthStep('dashboard');
      addLog('success', `User ${usernameInput} authenticated via Email OTP.`);
    } else {
      setAuthError('Invalid OTP Code');
      addLog('error', `Failed OTP attempt for ${usernameInput}`);
    }
  };

  // --- Signup Logic ---

  const handleInitiateSignup = (e) => {
    e.preventDefault();
    setAuthError('');

    if (passwordInput.length < 4) {
      setAuthError('Password too short (Min 4 chars)');
      return;
    }
    if (passwordInput !== confirmPasswordInput) {
      setAuthError('Passwords do not match');
      return;
    }
    if (!emailInput.includes('@')) {
      setAuthError('Invalid email address');
      return;
    }
    if (registeredUsers.find(u => u.username === usernameInput)) {
      setAuthError('Username already taken');
      return;
    }

    setIsSimulatingEmail(true);
    
    // Simulate sending Verification Email
    setTimeout(() => {
      setIsSimulatingEmail(false);
      setSignupStep('otp');
      addLog('info', `Verification code sent to ${emailInput} for new account registration.`);
    }, 1500);
  };

  const handleVerifySignupOTP = (e) => {
    e.preventDefault();
    if (otpInput === '123456') {
      // Create User
      const newUser = { 
        username: usernameInput, 
        password: passwordInput, 
        email: emailInput 
      };
      setRegisteredUsers([...registeredUsers, newUser]);
      
      addLog('success', `New account registered: ${usernameInput}`);
      alert("Account verified and created successfully! Please log in.");
      
      // Reset to Login
      setAuthStep('login');
      setSignupStep('details');
      resetInputs();
    } else {
      setAuthError('Invalid OTP Code');
    }
  };

  // --- File Operations ---

  const toggleEncryption = (fileId) => {
    setFiles(files.map(f => {
      if (f.id === fileId) {
        const newState = !f.encrypted;
        addLog(newState ? 'info' : 'warning', `File '${f.name}' was ${newState ? 'ENCRYPTED' : 'DECRYPTED'} using AES-256.`);
        return { ...f, encrypted: newState };
      }
      return f;
    }));
  };

  const deleteFile = (id) => {
    const file = files.find(f => f.id === id);
    setFiles(files.filter(f => f.id !== id));
    addLog('warning', `File '${file.name}' deleted.`);
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const name = file.name;
    const extension = name.split('.').pop().toLowerCase();
    const maliciousExtensions = ['exe', 'bat', 'sh', 'cmd', 'vbs'];

    if (maliciousExtensions.includes(extension)) {
      addLog('critical', `MALWARE BLOCKED: '${name}' contains executable payload.`);
      alert("SECURITY ALERT: Malicious file signature detected. Upload blocked.");
      return;
    }

    // Use FileReader to read the actual file content
    const reader = new FileReader();
    
    reader.onload = (event) => {
        const fileContent = event.target.result;
        
        const newFile = {
            id: generateId(),
            name: name,
            size: (file.size / 1024).toFixed(1) + ' KB',
            type: extension,
            owner: currentUser?.name || 'system',
            encrypted: false,
            content: fileContent // Stores actual text content or Base64 Data URL
        };
        
        setFiles([newFile, ...files]);
        addLog('success', `File '${name}' uploaded successfully.`);
    };

    reader.onerror = () => {
        addLog('error', `Error reading file: ${name}`);
        alert("Failed to read file content.");
    };

    // Determine reading method based on file type
    if (['png', 'jpg', 'jpeg', 'gif', 'pdf'].includes(extension)) {
        // Read binary files (Images, PDFs) as Data URL for display
        reader.readAsDataURL(file);
    } else {
        // Read others as text
        reader.readAsText(file);
    }
  };

  const handleRename = (fileId, newName) => {
    if (newName.length > 30) {
      addLog('critical', `BUFFER OVERFLOW BLOCKED: Rename input exceeded memory allocation (${newName.length} chars).`);
      alert("SECURITY WARNING: Input length exceeds buffer limit. Operation blocked to prevent memory corruption.");
      return;
    }
    setFiles(files.map(f => f.id === fileId ? { ...f, name: newName } : f));
    setModal(null);
    addLog('info', `File renamed to '${newName}'.`);
  };

  // Helper to open modal and reset zoom
  const openModal = (type, file) => {
      setModal({ type, file });
      setZoomLevel(100);
  }

  // --- Render Views ---

  // 1. SIGNUP VIEW
  if (authStep === 'signup') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-mono text-slate-200">
        <div className="bg-slate-800 border border-slate-700 p-8 rounded-xl shadow-2xl max-w-md w-full">
          <div className="flex items-center justify-center mb-6 text-emerald-400">
            <Shield className="w-10 h-10 mr-3" />
            <h1 className="text-xl font-bold tracking-tighter">REGISTER<span className="text-white">USER</span></h1>
          </div>

          {signupStep === 'details' ? (
            <form onSubmit={handleInitiateSignup} className="space-y-4 animate-in fade-in">
               <h2 className="text-center text-slate-400 mb-4 text-sm">ACCOUNT DETAILS</h2>
              <div>
                <label className="block text-xs uppercase tracking-widest mb-1 text-slate-500">Username</label>
                <input type="text" value={usernameInput} onChange={(e) => setUsernameInput(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 focus:border-emerald-500 focus:outline-none" />
              </div>
              <div>
                <label className="block text-xs uppercase tracking-widest mb-1 text-slate-500">Email Address</label>
                <input type="email" value={emailInput} onChange={(e) => setEmailInput(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 focus:border-emerald-500 focus:outline-none" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs uppercase tracking-widest mb-1 text-slate-500">Password</label>
                  <input type="password" value={passwordInput} onChange={(e) => setPasswordInput(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 focus:border-emerald-500 focus:outline-none" />
                </div>
                <div>
                  <label className="block text-xs uppercase tracking-widest mb-1 text-slate-500">Confirm</label>
                  <input type="password" value={confirmPasswordInput} onChange={(e) => setConfirmPasswordInput(e.target.value)} className="w-full bg-slate-900 border border-slate-700 rounded p-2 focus:border-emerald-500 focus:outline-none" />
                </div>
              </div>
              {authError && <div className="text-red-500 text-xs flex items-center"><AlertTriangle className="w-3 h-3 mr-1" /> {authError}</div>}
              <button disabled={isSimulatingEmail} className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded transition-all disabled:opacity-50">
                {isSimulatingEmail ? 'SENDING VERIFICATION...' : 'VERIFY EMAIL & REGISTER'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleVerifySignupOTP} className="space-y-6 animate-in slide-in-from-right-8">
               <div className="text-center">
                  <Mail className="w-12 h-12 mx-auto text-emerald-400 mb-2" />
                  <h2 className="text-xl font-bold">Verify Email</h2>
                  <p className="text-xs text-slate-400 mt-2">Code sent to <span className="text-white">{emailInput}</span></p>
               </div>
               
               <input 
                type="text" 
                placeholder="000000"
                maxLength="6"
                value={otpInput}
                onChange={(e) => setOtpInput(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-4 text-center text-2xl tracking-[1em] focus:border-emerald-500 focus:outline-none"
                autoFocus
              />
              <p className="text-xs text-center text-slate-500">(Use code: 123456)</p>
              {authError && <div className="text-red-500 text-sm flex items-center justify-center"><XCircle className="w-4 h-4 mr-2" /> {authError}</div>}
              
              <button className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded transition-all">
                CONFIRM ACCOUNT
              </button>
            </form>
          )}

          <div className="mt-4 text-center">
             <button onClick={() => { setAuthStep('login'); resetInputs(); }} className="text-xs text-emerald-500 hover:text-emerald-400 underline">
                Already have an account? Login
             </button>
          </div>
        </div>
      </div>
    );
  }

  // 2. LOGIN VIEW
  if (authStep === 'login') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-mono text-slate-200">
        <div className="bg-slate-800 border border-slate-700 p-8 rounded-xl shadow-2xl max-w-md w-full">
          <div className="flex items-center justify-center mb-6 text-emerald-400">
            <Shield className="w-12 h-12 mr-3" />
            <h1 className="text-2xl font-bold tracking-tighter">SECURE<span className="text-white">FILE</span></h1>
          </div>
          <h2 className="text-center text-slate-400 mb-6 text-sm">ENTER CREDENTIALS</h2>
          
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs uppercase tracking-widest mb-1 text-slate-500">Username</label>
              <input 
                type="text" 
                value={usernameInput}
                onChange={(e) => setUsernameInput(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-3 focus:border-emerald-500 focus:outline-none transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs uppercase tracking-widest mb-1 text-slate-500">Password</label>
              <input 
                type="password" 
                value={passwordInput}
                onChange={(e) => setPasswordInput(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-3 focus:border-emerald-500 focus:outline-none transition-colors"
              />
            </div>
            {authError && <div className="text-red-500 text-sm flex items-center"><AlertTriangle className="w-4 h-4 mr-2" /> {authError}</div>}
            
            <div className="bg-blue-900/20 border border-blue-900/50 p-3 rounded text-xs text-blue-300 mb-4">
               <span className="font-bold">Demo Hint:</span> Default User: <span className="text-white">admin</span> / Pass: <span className="text-white">password</span>
            </div>

            <button className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded transition-all">
              AUTHENTICATE
            </button>
          </form>
          <div className="mt-4 text-center">
             <button onClick={() => { setAuthStep('signup'); resetInputs(); }} className="text-xs text-emerald-500 hover:text-emerald-400 underline">
                New User? Create Account
             </button>
          </div>
          <div className="mt-6 text-xs text-center text-slate-600">
            Protected by AES-256 Encryption & Real-time Threat Detection
          </div>
        </div>
      </div>
    );
  }

  // 3. 2FA VIEW (Login Flow)
  if (authStep === '2fa') {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center p-4 font-mono text-slate-200">
        <div className="bg-slate-800 border border-slate-700 p-8 rounded-xl shadow-2xl max-w-md w-full text-center">
          <div className="mb-6 flex justify-center text-amber-400">
            <Mail className="w-12 h-12" />
          </div>
          <h2 className="text-xl font-bold mb-2">Login Verification</h2>
          
          {!otpSent ? (
            <div className="space-y-6 animate-in fade-in">
              <p className="text-slate-400 text-sm">
                Verify your identity to access the dashboard.
              </p>
              <div className="bg-slate-900 p-4 rounded border border-slate-700 text-sm text-slate-300">
                Account: <span className="text-emerald-400 font-bold">{usernameInput}</span>
              </div>
              <button 
                onClick={handleSendLoginOTP}
                disabled={isSimulatingEmail}
                className="w-full bg-amber-600 hover:bg-amber-500 text-white font-bold py-3 rounded transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
              >
                {isSimulatingEmail ? 'SENDING EMAIL...' : 'SEND OTP CODE'}
              </button>
            </div>
          ) : (
            <form onSubmit={handleVerifyLogin2FA} className="space-y-4 animate-in slide-in-from-right-8">
              <p className="text-emerald-400 text-sm mb-4 flex items-center justify-center">
                <CheckCircle className="w-4 h-4 mr-2" /> Code sent successfully!
              </p>
              
              <input 
                type="text" 
                placeholder="000000"
                maxLength="6"
                value={otpInput}
                onChange={(e) => setOtpInput(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-4 text-center text-2xl tracking-[1em] focus:border-amber-500 focus:outline-none"
                autoFocus
              />
               <p className="text-xs text-slate-500">(Use code: 123456)</p>

              {authError && <div className="text-red-500 text-sm flex items-center justify-center"><XCircle className="w-4 h-4 mr-2" /> {authError}</div>}
              
              <button className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold py-3 rounded transition-all">
                VERIFY & LOGIN
              </button>
              <button type="button" onClick={() => setOtpSent(false)} className="text-xs text-slate-500 hover:text-white underline mt-2">
                Didn't receive it? Resend
              </button>
            </form>
          )}
        </div>
      </div>
    );
  }

  // 4. DASHBOARD VIEW
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-emerald-500/30">
      
      {/* Navbar */}
      <nav className="bg-slate-900 border-b border-slate-800 h-16 flex items-center justify-between px-6">
        <div className="flex items-center space-x-3">
          <div className="bg-emerald-500/10 p-2 rounded-lg">
            <Shield className="w-6 h-6 text-emerald-500" />
          </div>
          <span className="font-bold text-lg tracking-tight">Secure<span className="text-emerald-500">File</span></span>
        </div>
        <div className="flex items-center space-x-6">
            <div className="hidden md:flex items-center space-x-2 text-xs text-emerald-400 bg-emerald-950/30 px-3 py-1 rounded-full border border-emerald-500/20">
                <Activity className="w-3 h-3" />
                <span>System Secure</span>
            </div>
            <div className="flex items-center space-x-2 text-sm text-slate-400">
                <User className="w-4 h-4" />
                <span>{currentUser?.name} <span className="text-xs opacity-50 uppercase tracking-wider">[{currentUser?.role}]</span></span>
            </div>
            <button onClick={() => { setAuthStep('login'); resetInputs(); }} className="text-xs text-red-400 hover:text-red-300">Logout</button>
        </div>
      </nav>

      <div className="flex h-[calc(100vh-64px)]">
        
        {/* Sidebar */}
        <aside className="w-64 bg-slate-900/50 border-r border-slate-800 hidden md:flex flex-col">
          <div className="p-6">
            <button className="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2 px-4 rounded-lg flex items-center justify-center transition-colors shadow-lg shadow-emerald-900/20">
              <label className="flex items-center cursor-pointer w-full justify-center">
                 <Upload className="w-4 h-4 mr-2" />
                 <span>Secure Upload</span>
                 <input type="file" className="hidden" onChange={handleFileUpload} />
              </label>
            </button>
          </div>
          <nav className="flex-1 px-4 space-y-2">
            <button 
                onClick={() => setActiveTab('files')}
                className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm transition-colors ${activeTab === 'files' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
            >
                <HardDrive className="w-4 h-4" />
                <span>My Drive</span>
            </button>
            <button 
                 onClick={() => setActiveTab('audit')}
                 className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm transition-colors ${activeTab === 'audit' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'}`}
            >
                <Terminal className="w-4 h-4" />
                <span>Security Audit Logs</span>
            </button>
          </nav>
          <div className="p-4 border-t border-slate-800 text-xs text-slate-500">
            <p>Storage: Encrypted (AES-256)</p>
            <p>Gateway: Active</p>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-8 overflow-auto bg-slate-950 relative">
          
          {activeTab === 'files' && (
            <>
            <header className="flex justify-between items-end mb-8">
                <div>
                    <h2 className="text-2xl font-bold text-white mb-1">My Files</h2>
                    <p className="text-slate-400 text-sm">Access Control: Role Based (RBAC)</p>
                </div>
                <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-slate-500 w-4 h-4" />
                    <input type="text" placeholder="Search encrypted files..." className="pl-10 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-200 focus:border-emerald-500 outline-none w-64" />
                </div>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                {files.map(file => {
                    const isAdmin = currentUser?.role === 'admin';
                    return (
                    <div key={file.id} className={`group relative bg-slate-900 border ${file.encrypted ? 'border-emerald-900/50' : 'border-slate-800'} hover:border-slate-600 rounded-xl p-5 transition-all duration-200 hover:-translate-y-1 shadow-xl`}>
                        <div className="flex justify-between items-start mb-4">
                            <div className={`p-3 rounded-lg ${file.encrypted ? 'bg-emerald-950 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                                <FileText className="w-6 h-6" />
                            </div>
                            <button 
                                onClick={() => toggleEncryption(file.id)}
                                className={`p-2 rounded-full transition-colors ${file.encrypted ? 'text-emerald-400 hover:bg-emerald-900/30' : 'text-amber-500 hover:bg-amber-900/30'}`}
                                title={file.encrypted ? "File Encrypted" : "File Unprotected"}
                            >
                                {file.encrypted ? <Lock className="w-4 h-4" /> : <Unlock className="w-4 h-4" />}
                            </button>
                        </div>
                        
                        <h3 className="font-medium text-slate-200 truncate mb-1" title={file.name}>{file.name}</h3>
                        <div className="flex justify-between text-xs text-slate-500 mb-4">
                            <span>{file.size}</span>
                            <span className="uppercase">{file.type}</span>
                        </div>

                        <div className="grid grid-cols-4 gap-2 pt-4 border-t border-slate-800/50">
                             <button onClick={() => openModal('view', file)} className="flex justify-center text-slate-400 hover:text-emerald-400" title="View Content"><Eye className="w-4 h-4" /></button>
                             <button onClick={() => openModal('rename', file)} className="flex justify-center text-slate-400 hover:text-blue-400" title="Rename (Input Checked)"><Terminal className="w-4 h-4" /></button>
                             
                             {/* Secure Share - Admin Only */}
                             <button 
                                onClick={() => isAdmin ? openModal('share', file) : addLog('warning', `ACCESS DENIED: User ${currentUser.name} attempted unauthorized SHARE on ${file.name}`)} 
                                className={`flex justify-center ${isAdmin ? 'text-slate-400 hover:text-amber-400' : 'text-slate-700 cursor-not-allowed'}`} 
                                title={isAdmin ? "Secure Share" : "Restricted: Admin Only"}
                             >
                                <Share2 className="w-4 h-4" />
                             </button>

                             {/* Delete - Admin Only */}
                             <button 
                                onClick={() => isAdmin ? deleteFile(file.id) : addLog('critical', `ACCESS DENIED: User ${currentUser.name} attempted unauthorized DELETE on ${file.name}`)} 
                                className={`flex justify-center ${isAdmin ? 'text-slate-400 hover:text-red-400' : 'text-slate-700 cursor-not-allowed'}`} 
                                title={isAdmin ? "Delete" : "Restricted: Admin Only"}
                             >
                                <Trash2 className="w-4 h-4" />
                             </button>
                        </div>
                    </div>
                )})}
            </div>
            </>
          )}

          {activeTab === 'audit' && (
              <div className="max-w-4xl mx-auto">
                  <h2 className="text-2xl font-bold text-white mb-6 flex items-center">
                      <Terminal className="w-6 h-6 mr-2 text-amber-500" />
                      Security Event Logs
                  </h2>
                  <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
                      <table className="w-full text-left text-sm">
                          <thead className="bg-slate-950 text-slate-400 uppercase text-xs">
                              <tr>
                                  <th className="px-6 py-4">Timestamp</th>
                                  <th className="px-6 py-4">Level</th>
                                  <th className="px-6 py-4">Event Message</th>
                              </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800">
                              {logs.map((log, idx) => (
                                  <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                                      <td className="px-6 py-4 text-slate-500 font-mono">{log.time}</td>
                                      <td className="px-6 py-4">
                                          <span className={`px-2 py-1 rounded text-xs font-bold uppercase
                                            ${log.type === 'info' ? 'bg-blue-900/30 text-blue-400' : ''}
                                            ${log.type === 'success' ? 'bg-emerald-900/30 text-emerald-400' : ''}
                                            ${log.type === 'warning' ? 'bg-amber-900/30 text-amber-400' : ''}
                                            ${log.type === 'critical' ? 'bg-red-900/30 text-red-400 animate-pulse' : ''}
                                            ${log.type === 'error' ? 'bg-red-900/30 text-red-400' : ''}
                                          `}>
                                              {log.type}
                                          </span>
                                      </td>
                                      <td className="px-6 py-4 text-slate-300">{log.message}</td>
                                  </tr>
                              ))}
                          </tbody>
                      </table>
                  </div>
              </div>
          )}

        </main>
      </div>

      {/* Modals */}
      {modal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            <div className={`bg-slate-800 border border-slate-700 rounded-xl shadow-2xl w-full overflow-hidden animate-in fade-in zoom-in duration-200 flex flex-col ${modal.type === 'view' ? 'max-w-4xl h-[80vh]' : 'max-w-lg'}`}>
                
                {/* Modal Header */}
                <div className="bg-slate-900 px-6 py-4 flex items-center justify-between border-b border-slate-700 shrink-0">
                    {/* Left Side: Close Button (Cross Sign) */}
                    <div className="flex items-center">
                        <button onClick={() => setModal(null)} className="text-slate-500 hover:text-red-400 mr-4 transition-colors" title="Close">
                            <XCircle className="w-6 h-6" />
                        </button>
                        <h3 className="font-bold text-white flex items-center">
                            {modal.type === 'view' && <><Eye className="w-4 h-4 mr-2 text-emerald-400"/> Secure Viewer</>}
                            {modal.type === 'share' && <><Share2 className="w-4 h-4 mr-2 text-amber-400"/> Generate Secure Link</>}
                            {modal.type === 'rename' && <><Terminal className="w-4 h-4 mr-2 text-blue-400"/> Modify File Record</>}
                        </h3>
                    </div>
                    
                    {/* Right Side: Zoom Controls (Only for View) */}
                    {modal.type === 'view' && (
                        <div className="flex items-center space-x-2 bg-slate-800 rounded-lg p-1 border border-slate-700">
                            <button onClick={() => setZoomLevel(Math.max(50, zoomLevel - 10))} className="p-1 hover:bg-slate-700 rounded text-slate-400 hover:text-white" title="Zoom Out">
                                <Minus className="w-4 h-4" />
                            </button>
                            <span className="text-xs font-mono w-12 text-center text-slate-300">{zoomLevel}%</span>
                            <button onClick={() => setZoomLevel(Math.min(300, zoomLevel + 10))} className="p-1 hover:bg-slate-700 rounded text-slate-400 hover:text-white" title="Zoom In">
                                <Plus className="w-4 h-4" />
                            </button>
                        </div>
                    )}
                </div>

                {/* Modal Content */}
                <div className="p-6 overflow-hidden flex-1 flex flex-col">
                    
                    {/* VIEW MODAL */}
                    {modal.type === 'view' && (
                        <div className="space-y-4 h-full flex flex-col">
                            <div className="flex items-center justify-between text-sm text-slate-400 shrink-0">
                                <span>Filename: <span className="text-white">{modal.file.name}</span></span>
                                <span>Status: {modal.file.encrypted ? <span className="text-emerald-400">Encrypted</span> : <span className="text-amber-500">Plaintext</span>}</span>
                            </div>
                            
                            {/* Scrollable Content Area */}
                            <div className="bg-slate-950 p-4 rounded border border-slate-700 font-mono text-sm flex-1 overflow-auto relative">
                                <div 
                                    className="min-h-full min-w-full flex items-center justify-center transition-all duration-200 origin-top-left"
                                    style={{
                                        // We apply scaling differently based on content type for best UX
                                        width: ['png', 'jpg', 'jpeg', 'gif'].includes(modal.file.type) ? 'fit-content' : '100%',
                                        height: ['png', 'jpg', 'jpeg', 'gif'].includes(modal.file.type) ? 'fit-content' : '100%'
                                    }}
                                >
                                    {modal.file.encrypted ? (
                                        <span 
                                            className="break-all text-emerald-600 blur-[2px] select-none text-left w-full"
                                            style={{ fontSize: `${zoomLevel}%` }}
                                        >
                                            U2FsdGVkX1+439s0s0d7s9s0d7f6g5h4j3k2l1... [ENCRYPTED DATA STREAM] ... 8s7d6f5g4h3j2k1l0
                                        </span>
                                    ) : (
                                        // Render content based on type
                                        <>
                                            {['png', 'jpg', 'jpeg', 'gif'].includes(modal.file.type) ? (
                                                <img 
                                                    src={modal.file.content} 
                                                    alt="File content" 
                                                    className="object-contain rounded transition-all duration-200"
                                                    style={{ 
                                                        width: `${zoomLevel}%`, 
                                                        maxWidth: 'none' // Allow overflowing for scroll
                                                    }} 
                                                />
                                            ) : modal.file.type === 'pdf' && modal.file.content.startsWith('data:') ? (
                                                <object
                                                    data={modal.file.content}
                                                    type="application/pdf"
                                                    className="rounded bg-slate-200 shadow-inner"
                                                    style={{ 
                                                        width: `${zoomLevel}%`, 
                                                        minHeight: '100%',
                                                        height: `${zoomLevel}%`
                                                    }}
                                                >
                                                    <div className="flex flex-col items-center justify-center h-full text-slate-500 p-8 text-center">
                                                        <AlertTriangle className="w-12 h-12 mb-4 text-amber-500 opacity-50" />
                                                        <p className="font-bold">Preview Unavailable</p>
                                                        <p className="text-sm mb-4">Your browser may have blocked the PDF preview.</p>
                                                        <a 
                                                            href={modal.file.content} 
                                                            download={modal.file.name} 
                                                            className="bg-emerald-600 text-white px-4 py-2 rounded hover:bg-emerald-500 transition-colors"
                                                        >
                                                            Download PDF to View
                                                        </a>
                                                    </div>
                                                </object>
                                            ) : (
                                                <pre 
                                                    className="text-slate-300 whitespace-pre-wrap font-mono text-left w-full h-full"
                                                    style={{ fontSize: `${(zoomLevel / 100) * 0.875}rem` }}
                                                >
                                                    {modal.file.content}
                                                </pre>
                                            )}
                                        </>
                                    )}
                                </div>
                            </div>
                            {modal.file.encrypted && (
                                <p className="text-xs text-center text-amber-500 flex items-center justify-center shrink-0">
                                    <Lock className="w-3 h-3 mr-1" /> Decrypt file to view contents
                                </p>
                            )}
                        </div>
                    )}

                    {/* SHARE MODAL */}
                    {modal.type === 'share' && (
                        <div className="text-center space-y-4">
                            <div className="p-4 bg-slate-900 rounded-lg border border-dashed border-slate-700">
                                <p className="text-xs text-slate-500 mb-1">One-time Secure Link</p>
                                <code className="text-emerald-400 block break-all bg-black/20 p-2 rounded">
                                    https://securefile.io/share/{Math.random().toString(36).substring(7)}?key=aes256
                                </code>
                            </div>
                            <button className="bg-emerald-600 text-white px-4 py-2 rounded w-full hover:bg-emerald-500" onClick={() => {addLog('info', `Secure link generated for ${modal.file.name}`); setModal(null);}}>
                                Copy Link to Clipboard
                            </button>
                        </div>
                    )}

                    {/* RENAME MODAL */}
                    {modal.type === 'rename' && (
                        <div className="space-y-4">
                             <p className="text-sm text-slate-400">Enter new filename. <span className="text-red-400">Warning: Input buffer limited to 30 chars.</span></p>
                             <form onSubmit={(e) => {
                                 e.preventDefault();
                                 handleRename(modal.file.id, e.target.elements.newName.value);
                             }}>
                                 <input 
                                    name="newName"
                                    defaultValue={modal.file.name}
                                    className="w-full bg-slate-900 border border-slate-700 rounded p-3 text-white focus:border-blue-500 outline-none"
                                    autoFocus
                                 />
                                 <div className="flex space-x-3 mt-4">
                                     <button type="button" onClick={() => setModal(null)} className="flex-1 py-2 text-slate-400 hover:text-white">Cancel</button>
                                     <button type="submit" className="flex-1 bg-blue-600 hover:bg-blue-500 text-white py-2 rounded">Save Changes</button>
                                 </div>
                             </form>
                        </div>
                    )}
                </div>
            </div>
        </div>
      )}

    </div>
  );
}