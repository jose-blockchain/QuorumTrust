// QuorumTrust GUI Application

let currentView = 'documents';
let currentFile = null;
let currentFileIsNetwork = false;
let allProposals = [];
let proposalFilter = 'all';
let currentNodeDigest = null;
let currentActiveMembers = 0;
let currentIsActiveMember = false;
let membersByDigest = {};

// --- Sanitization ---
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  const div = document.createElement('div');
  div.appendChild(document.createTextNode(str));
  return div.innerHTML;
}

// --- Toast ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

// --- API ---
async function api(endpoint, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`/api${endpoint}`, opts);
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(err.error || err.detail || 'Request failed');
  }
  return resp.json();
}

// --- Navigation ---
function switchView(view) {
  currentView = view;
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.view === view);
  });
  document.querySelectorAll('.view-panel').forEach(el => {
    el.style.display = 'none';
  });
  document.getElementById(`view-${view}`).style.display = 'block';

  if (view === 'governance') loadProposals();
  if (view === 'members') loadMembers();
  if (view === 'documents') {
    api('/governance/sync', 'POST').catch(() => {});
    loadFiles();
  }
}

// --- Status ---
async function loadStatus() {
  try {
    const data = await api('/status');
    document.getElementById('networkName').textContent = data.network_name;
    document.getElementById('memberCount').textContent = data.active_members;
    document.getElementById('proposalCount').textContent = data.pending_proposals;
    document.getElementById('nodeDigest').textContent = data.node_digest.substring(0, 12);

    // remember full digest, active member count, and membership status
    currentNodeDigest = data.node_digest;
    currentActiveMembers = data.active_members || 0;
    currentIsActiveMember = data.is_active_member === true;

    const awaitingMyVote = currentIsActiveMember ? (data.proposals_awaiting_my_vote ?? data.pending_proposals) : 0;

    const nameEl = document.getElementById('nodeName');
    if (data.node_name) {
      nameEl.textContent = data.node_name;
      nameEl.style.display = '';
    } else {
      nameEl.style.display = 'none';
    }

    const badge = document.getElementById('pendingBadge');
    if (awaitingMyVote > 0) {
      badge.textContent = awaitingMyVote;
      badge.style.display = '';
    } else {
      badge.style.display = 'none';
    }
  } catch (e) {
    document.getElementById('networkName').textContent = 'Node Offline';
  }
}

// --- Files ---
let fileList = [];

async function loadFiles() {
  try {
    fileList = await api('/files');
    renderFileTree(fileList);
    // If current file was renamed (no longer in list), update to the new path
    if (currentFile && !fileList.find(f => f.path === currentFile && !f.is_dir)) {
      const basename = currentFile.split('/').pop();
      const dir = currentFile.substring(0, currentFile.length - basename.length);
      const match = fileList.find(f => !f.is_dir && f.path.startsWith(dir) && f.path !== currentFile);
      if (match) {
        currentFile = match.path;
        currentFileIsNetwork = match.is_network;
        openFile(match.path, match.is_network);
      }
    }
  } catch (e) {
    document.getElementById('fileTree').innerHTML =
      '<div style="padding:16px;color:var(--mid-gray);font-size:13px">Node unavailable</div>';
  }
}

function renderFileTree(files) {
  const container = document.getElementById('fileTree');
  if (!files || files.length === 0) {
    container.innerHTML = '<div style="padding:16px;color:var(--mid-gray);font-size:13px">No files yet</div>';
    return;
  }

  container.innerHTML = '';
  for (const f of files) {
    const row = document.createElement('div');
    row.className = 'file-row';
    row.style.display = 'flex';
    row.style.alignItems = 'center';
    row.style.gap = '4px';

    if (f.is_dir) {
      const el = document.createElement('div');
      el.className = 'file-item directory';
      el.style.flex = '1';
      el.innerHTML = `<span class="file-icon">&#128193;</span><span>${escapeHtml(f.path)}</span>`;
      row.appendChild(el);
    } else {
      const isLocal = !f.is_network;
      if (isLocal) {
        const btnPropose = document.createElement('button');
        btnPropose.className = 'btn-propose-file';
        btnPropose.title = 'Propose to network';
        btnPropose.textContent = '\u2794'; /* ➔ heavy arrow */
        btnPropose.addEventListener('click', (e) => { e.stopPropagation(); proposeToNetwork(f.path); });
        row.appendChild(btnPropose);
      }
      const el = document.createElement('div');
      const statusClass = f.tracking_status === 'Tracked' ? 'tracked'
        : f.tracking_status === 'PendingVote' ? 'pending'
        : 'untracked';
      const version = f.version ? `v${f.version}` : '';
      const isFinal = f.doc_status === 'Final';
      const finalTag = isFinal ? '<span class="file-final-tag">FINAL</span>' : '';
      const signedTag = f.threshold_signature_hex ? `<span class="file-signed-tag">${f.frost_threshold || '?'}/${f.frost_total || '?'}</span>` : '';
      const icon = getFileIcon(f.path);
      el.className = `file-item ${statusClass}`;
      el.style.flex = '1';
      el.innerHTML = `<span class="file-icon">${icon}</span><span>${escapeHtml(f.path.split('/').pop())}</span><span class="file-version">${version}</span>${finalTag}${signedTag}`;
      el.dataset.filePath = f.path;
      el.dataset.isNetwork = f.is_network ? '1' : '0';
      el.addEventListener('click', () => openFile(f.path, f.is_network));
      row.appendChild(el);
    }
    container.appendChild(row);
  }
}

function getFileIcon(path) {
  const ext = path.split('.').pop().toLowerCase();
  if (['md', 'markdown'].includes(ext)) return '&#128220;';
  if (['js', 'ts', 'jsx', 'tsx'].includes(ext)) return '&#9881;';
  if (['rs', 'py', 'go', 'java', 'c', 'cpp'].includes(ext)) return '&#128187;';
  if (['json', 'toml', 'yaml', 'yml'].includes(ext)) return '&#128203;';
  return '&#128196;';
}

async function openFile(path, isNetwork) {
  currentFile = path;
  currentFileIsNetwork = isNetwork ?? fileList.find(f => !f.is_dir && f.path === path)?.is_network ?? false;
  try {
    const data = await api(`/files/read?path=${encodeURIComponent(path)}`);
    renderFileEditor(path, data.content, isNetwork);
  } catch (e) {
    showToast('Failed to read file: ' + e.message, 'error');
  }
}

function renderFileEditor(path, content, isNetwork = false) {
  const container = document.getElementById('documentContent');
  container.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'content-header';

  const title = document.createElement('h1');
  title.className = 'content-title';
  title.textContent = path;

  const btnGroup = document.createElement('div');
  btnGroup.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px';

  const btnFork = document.createElement('button');
  btnFork.className = 'btn btn-outline btn-sm';
  btnFork.textContent = 'Fork';
  btnFork.addEventListener('click', () => forkFile(path));

  const btnFinalize = document.createElement('button');
  btnFinalize.className = 'btn btn-outline btn-sm';
  btnFinalize.textContent = 'Finalize';
  btnFinalize.addEventListener('click', () => finalizeFile(path));
  if (!isNetwork) { btnFinalize.disabled = true; btnFinalize.title = 'File must be on network'; }

  const btnSave = document.createElement('button');
  btnSave.className = 'btn btn-primary btn-sm' + (isNetwork ? '' : ' btn-visually-disabled');
  btnSave.textContent = 'Save & Propose';
  btnSave.title = isNetwork ? 'Save changes and create edit proposal' : 'File must be on network first. Use the → button in the sidebar to propose it.';
  btnSave.addEventListener('click', () => saveFile());

  if (isNetwork) {
    const btnRename = document.createElement('button');
    btnRename.className = 'btn btn-outline btn-sm';
    btnRename.textContent = 'Propose Rename';
    btnRename.addEventListener('click', () => proposeRenameFile(path));
    btnGroup.append(btnFork, btnFinalize, btnSave, btnRename);
  } else {
    const btnRename = document.createElement('button');
    btnRename.className = 'btn btn-outline btn-sm';
    btnRename.textContent = 'Rename';
    btnRename.addEventListener('click', () => renameLocalFile(path));
    btnGroup.append(btnFork, btnFinalize, btnSave, btnRename);
  }
  header.append(title, btnGroup);
  container.appendChild(header);

  // FROST threshold signature banner
  const fileInfo = fileList.find(f => f.path === path);
  if (fileInfo && fileInfo.threshold_signature_hex) {
    const sigBanner = document.createElement('div');
    sigBanner.className = 'frost-signature-banner';
    const sigShort = fileInfo.threshold_signature_hex.substring(0, 48);
    const t = fileInfo.frost_threshold || '?';
    const n = fileInfo.frost_total || '?';
    sigBanner.innerHTML = `<div class="frost-sig-header"><span class="frost-sig-icon">&#x1F58A;</span> <strong>FROST Threshold Signature</strong> <span class="frost-sig-scheme">${t}-of-${n}</span></div><div class="frost-sig-hex"><code>${escapeHtml(sigShort)}...</code></div>`;
    container.appendChild(sigBanner);
  } else if (fileInfo && fileInfo.doc_status === 'Final' && !fileInfo.threshold_signature_hex) {
    const pendingBanner = document.createElement('div');
    pendingBanner.className = 'frost-signature-banner frost-sig-pending';
    pendingBanner.innerHTML = `<span class="frost-sig-icon">&#9203;</span> <strong>FROST signing in progress...</strong>`;
    container.appendChild(pendingBanner);
  }

  // Tabs
  const tabs = document.createElement('div');
  tabs.className = 'tabs';

  const tabEdit = document.createElement('div');
  tabEdit.className = 'tab active';
  tabEdit.textContent = 'Edit';
  tabEdit.addEventListener('click', () => {
    tabEdit.classList.add('active');
    tabPreview.classList.remove('active');
    editorDiv.style.display = '';
    previewDiv.style.display = 'none';
  });

  const tabPreview = document.createElement('div');
  tabPreview.className = 'tab';
  tabPreview.textContent = 'Preview';
  tabPreview.addEventListener('click', () => {
    tabPreview.classList.add('active');
    tabEdit.classList.remove('active');
    editorDiv.style.display = 'none';
    previewDiv.style.display = '';
    renderPreview();
  });

  tabs.append(tabEdit, tabPreview);
  container.appendChild(tabs);

  // Editor
  const editorDiv = document.createElement('div');
  editorDiv.id = 'editorTab';
  const textarea = document.createElement('textarea');
  textarea.className = 'editor-textarea';
  textarea.id = 'fileEditor';
  textarea.value = content;
  editorDiv.appendChild(textarea);
  container.appendChild(editorDiv);

  // Preview
  const previewDiv = document.createElement('div');
  previewDiv.id = 'previewTab';
  previewDiv.style.display = 'none';
  const pane = document.createElement('div');
  pane.className = 'preview-pane';
  pane.id = 'previewPane';
  previewDiv.appendChild(pane);
  container.appendChild(previewDiv);
}

function renderPreview() {
  const content = document.getElementById('fileEditor').value;
  const pane = document.getElementById('previewPane');
  const ext = currentFile ? currentFile.split('.').pop().toLowerCase() : '';

  if (['md', 'markdown'].includes(ext)) {
    pane.innerHTML = simpleMarkdown(content);
  } else {
    pane.innerHTML = `<pre><code>${escapeHtml(content)}</code></pre>`;
  }
}

function simpleMarkdown(text) {
  let html = escapeHtml(text);
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/\n\n/g, '</p><p>');
  html = '<p>' + html + '</p>';
  return html;
}

async function saveFile() {
  if (!currentFile) return;
  if (!currentFileIsNetwork) {
    showToast('File must be on network first. Use the → button in the sidebar to propose it.', 'error');
    return;
  }
  const content = document.getElementById('fileEditor').value;
  try {
    const data = await api('/files/edit', 'POST', {
      path: currentFile,
      new_content: content,
    });
    showToast(`Edit proposal created (+${data.additions} -${data.deletions}). Go to Governance to vote.`, 'success');
    loadProposals();
    loadStatus();
  } catch (e) {
    console.error('Save & Propose failed:', e);
    showToast('Save failed: ' + e.message, 'error');
  }
}

async function forkFile(path) {
  const newName = prompt('New name for fork (leave empty for auto-name):');
  try {
    const data = await api('/files/fork', 'POST', {
      path: path,
      new_name: newName || null,
      share: false,
    });
    showToast(`Forked to: ${data.forked_path}`, 'success');
    loadFiles();
  } catch (e) {
    showToast('Fork failed: ' + e.message, 'error');
  }
}

async function finalizeFile(path) {
  if (!confirm(`Mark "${path}" as final? This cannot be undone.`)) return;
  try {
    await api('/files/finalize', 'POST', { path });
    showToast('Finalize proposal created', 'success');
    await loadFiles();
    openFile(path, true);
  } catch (e) {
    showToast('Finalize failed: ' + e.message, 'error');
  }
}

async function proposeToNetwork(path) {
  try {
    const data = await api('/files/propose-add', 'POST', { path });
    showToast('Add-file proposal created', 'success');
    loadFiles();
  } catch (e) {
    showToast('Propose failed: ' + e.message, 'error');
  }
}

async function renameLocalFile(path) {
  const newName = prompt('New filename (e.g. doc-v2.md):');
  if (!newName || !newName.trim()) return;
  try {
    const data = await api('/files/rename-local', 'POST', { path, new_name: newName.trim() });
    showToast('File renamed locally', 'success');
    currentFile = data.path;
    loadFiles();
    const content = (await api(`/files/read?path=${encodeURIComponent(data.path)}`)).content;
    const f = fileList.find(x => x.path === data.path);
    renderFileEditor(data.path, content, f ? f.is_network : false);
  } catch (e) {
    showToast('Rename failed: ' + e.message, 'error');
  }
}

async function proposeRenameFile(path) {
  const newName = prompt('New filename for network doc:');
  if (!newName || !newName.trim()) return;
  try {
    await api('/files/propose-rename', 'POST', { path, new_name: newName.trim() });
    showToast('Rename proposal created', 'success');
  } catch (e) {
    showToast('Propose rename failed: ' + e.message, 'error');
  }
}

// --- Proposals ---
async function loadProposals() {
  try {
    allProposals = await api('/proposals');
    renderProposals();
  } catch (e) {
    document.getElementById('proposalsList').innerHTML =
      '<div class="empty-state"><div class="empty-state-text">Could not load proposals</div></div>';
  }
}

function filterProposals(filter) {
  proposalFilter = filter;
  document.querySelectorAll('.tabs .tab[data-filter]').forEach(t => {
    t.classList.toggle('active', t.dataset.filter === filter);
  });
  renderProposals();
}

function renderProposals() {
  const container = document.getElementById('proposalsList');
  let filtered = allProposals;
  if (proposalFilter !== 'all') {
    filtered = allProposals.filter(p => p.status === proposalFilter);
  }

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-state-icon">&#9878;</div><div class="empty-state-text">No proposals</div></div>';
    return;
  }

  container.innerHTML = '';
  for (const p of filtered) {
    const statusClass = p.status.toLowerCase();
    const typeLabel = formatProposalType(p.proposal_type);
    const totalVotes = Object.keys(p.votes || {}).length;
    const accepts = Object.values(p.votes || {}).filter(v => v.choice === 'Accept').length;
    const rejects = totalVotes - accepts;
    const userVote = currentNodeDigest && p.votes && p.votes[currentNodeDigest];
    const neededAccepts = currentActiveMembers > 0
      ? Math.floor((currentActiveMembers * 2) / 3) + 1
      : 0;

    const card = document.createElement('div');
    card.className = `proposal-card ${statusClass}`;

    const proposerName = memberName(p.proposer_digest);
    let cardHtml = `
      <div class="proposal-header">
        <span class="proposal-type">${escapeHtml(typeLabel)}</span>
        <span class="proposal-status ${statusClass}">${escapeHtml(p.status)}</span>
      </div>
      <div class="proposal-proposer">Proposed by: <strong>${escapeHtml(proposerName)}</strong> <span class="proposal-digest">${escapeHtml((p.proposer_digest || '').substring(0, 12))}</span></div>
      <div class="proposal-body">${formatProposalDetail(p.proposal_type)}</div>
      <div class="vote-stats">
        <span style="color:var(--green)">Accept: ${accepts}</span>
        <span style="color:var(--red-reject)">Reject: ${rejects}</span>
        <span>Needed: ${neededAccepts}</span>
      </div>
    `;
    card.innerHTML = cardHtml;

    // Only show voting UI to active members
    if (currentIsActiveMember) {
      if (userVote) {
        const info = document.createElement('div');
        info.style.fontSize = '12px';
        info.style.color = 'var(--mid-gray)';
        const label = userVote.choice === 'Accept' ? 'You voted: Accept' : 'You voted: Reject';
        info.textContent = label;
        card.appendChild(info);
      } else if (p.status === 'Pending') {
        const actions = document.createElement('div');
        actions.className = 'proposal-actions';

        const btnAccept = document.createElement('button');
        btnAccept.className = 'btn btn-accept btn-sm';
        btnAccept.textContent = 'Accept';
        btnAccept.addEventListener('click', () => voteOnProposal(p.id, 'accept'));

        const btnReject = document.createElement('button');
        btnReject.className = 'btn btn-reject btn-sm';
        btnReject.textContent = 'Reject';
        btnReject.addEventListener('click', () => voteOnProposal(p.id, 'reject'));

        actions.append(btnAccept, btnReject);
        card.appendChild(actions);
      }
    }

    container.appendChild(card);
  }
}

function formatProposalType(pt) {
  if (!pt) return 'Unknown';
  if (pt.AddMember) return 'Add Member';
  if (pt.ExpelMember) return 'Expel Member';
  if (pt.AddFile) return 'Add File';
  if (pt.EditFile) return 'Edit File';
  if (pt.RemoveFile) return 'Remove File';
  if (pt.MarkFinal) return 'Mark Final';
  if (pt.ChangeFileName) return 'Rename File';
  if (pt.ChangeMemberName) return 'Change Name';
  if (pt.ChangeMemberKey) return 'Change Key';
  return Object.keys(pt)[0] || 'Unknown';
}

function formatProposalDetail(pt) {
  if (!pt) return '';
  if (pt.AddMember) return `Add member: ${escapeHtml(pt.AddMember.display_name || pt.AddMember.public_key_hex.substring(0, 16) + '...')}`;
  if (pt.ExpelMember) return `Expel: ${escapeHtml(pt.ExpelMember.member_digest.substring(0, 16))}...`;
  if (pt.AddFile) return `Add file: <strong>${escapeHtml(pt.AddFile.path)}</strong>`;
  if (pt.EditFile) {
    let html = `Edit: <strong>${escapeHtml(pt.EditFile.path)}</strong>`;
    if (pt.EditFile.diff) {
      html += renderDiffHtml(pt.EditFile.diff);
    }
    return html;
  }
  if (pt.RemoveFile) return `Remove: <strong>${escapeHtml(pt.RemoveFile.path)}</strong>`;
  if (pt.MarkFinal) return `Finalize: <strong>${escapeHtml(pt.MarkFinal.path)}</strong>`;
  if (pt.ChangeFileName) return `Rename: <strong>${escapeHtml(pt.ChangeFileName.path)}</strong> → <strong>${escapeHtml(pt.ChangeFileName.new_name)}</strong>`;
  return JSON.stringify(pt);
}

function renderDiffHtml(diffText) {
  const lines = diffText.split('\n');
  let html = '<div class="diff-view" style="margin-top:8px;max-height:300px;overflow:auto;border:1px solid var(--border);border-radius:4px;padding:8px">';
  for (const line of lines) {
    const escaped = escapeHtml(line);
    if (line.startsWith('@@')) {
      html += `<div class="diff-header">${escaped}</div>`;
    } else if (line.startsWith('+')) {
      html += `<div class="diff-add">${escaped}</div>`;
    } else if (line.startsWith('-')) {
      html += `<div class="diff-del">${escaped}</div>`;
    } else {
      html += `<div>${escaped}</div>`;
    }
  }
  html += '</div>';
  return html;
}

async function voteOnProposal(id, choice) {
  try {
    const result = await api(`/proposals/${id}/vote`, 'POST', { choice });
    showToast(`Vote cast: ${choice} (${result.status})`, 'success');
    loadProposals();
    loadStatus();
    loadMembers(); // refresh when AddMember/ExpelMember proposals resolve
  } catch (e) {
    showToast('Vote failed: ' + e.message, 'error');
  }
}

// --- Members ---
async function loadMembers() {
  try {
    const members = await api('/members');
    membersByDigest = {};
    for (const m of members) {
      membersByDigest[m.identity.digest] = m.identity.display_name || 'Anonymous';
    }
    renderMembers(members);
  } catch (e) {
    document.getElementById('membersList').innerHTML = '<div class="empty-state"><div class="empty-state-text">Could not load members</div></div>';
  }
}

function memberName(digest) {
  if (!digest) return 'Unknown';
  return membersByDigest[digest] || digest.substring(0, 12) + '...';
}

function renderMembers(members) {
  const container = document.getElementById('membersList');
  if (!members || members.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="empty-state-text">No members</div></div>';
    return;
  }

  const active = members.filter(m => m.status === 'Active' || m.status === 'PendingJoin');
  const expelled = members.filter(m => m.status === 'Expelled');

  container.innerHTML = '';

  for (const m of active) {
    container.appendChild(buildMemberRow(m));
  }

  if (expelled.length > 0) {
    const divider = document.createElement('div');
    divider.className = 'member-divider';
    divider.innerHTML = '<span>Expelled Members</span>';
    container.appendChild(divider);
    for (const m of expelled) {
      container.appendChild(buildMemberRow(m));
    }
  }

  container.querySelectorAll('.btn-expel-member').forEach(btn => {
    btn.addEventListener('click', () => {
      confirmExpelMember(btn.dataset.digest, btn.dataset.name);
    });
  });
}

function buildMemberRow(m) {
  const name = m.identity.display_name || 'Anonymous';
  const initial = name.charAt(0).toUpperCase();
  const statusClass = m.status.toLowerCase();
  const statusLabel = m.status === 'Active' ? 'Active'
    : m.status === 'PendingJoin' ? 'Pending'
    : 'Expelled';
  const isExpelled = m.status === 'Expelled';

  const row = document.createElement('div');
  row.className = 'member-row' + (isExpelled ? ' member-expelled' : '');

  const isSelf = m.identity.digest === currentNodeDigest;
  const canExpel = m.status === 'Active' && !isSelf && currentIsActiveMember;
  const expelBtn = canExpel
    ? `<button class="btn btn-danger btn-sm btn-expel-member" data-digest="${escapeHtml(m.identity.digest)}" data-name="${escapeHtml(name)}">Expel</button>`
    : '';

  row.innerHTML = `
    <div class="member-avatar${isExpelled ? ' avatar-expelled' : ''}">${initial}</div>
    <div class="member-info">
      <div class="member-name">${escapeHtml(name)}${isSelf ? ' <span style="opacity:0.5">(you)</span>' : ''}</div>
      <div class="member-digest">${escapeHtml(m.identity.digest.substring(0, 24))}...</div>
    </div>
    <div class="member-actions">
      <span class="member-status ${statusClass}">${statusLabel}</span>
      ${expelBtn}
    </div>
  `;
  return row;
}

function confirmExpelMember(digest, name) {
  const frag = document.createElement('div');

  const title = document.createElement('div');
  title.className = 'modal-title';
  title.textContent = 'Expel Member';

  const msg = document.createElement('p');
  msg.style.margin = '12px 0';
  msg.innerHTML = `Are you sure you want to propose expelling <strong>${escapeHtml(name)}</strong>?<br><small style="opacity:0.6">${escapeHtml(digest.substring(0, 24))}...</small>`;

  const actions = document.createElement('div');
  actions.className = 'modal-actions';

  const btnCancel = document.createElement('button');
  btnCancel.className = 'btn btn-outline';
  btnCancel.textContent = 'Cancel';
  btnCancel.addEventListener('click', closeModal);

  const btnExpel = document.createElement('button');
  btnExpel.className = 'btn btn-danger';
  btnExpel.textContent = 'Propose Expel';
  btnExpel.addEventListener('click', () => expelMember(digest));

  actions.append(btnCancel, btnExpel);
  frag.append(title, msg, actions);
  showModal(frag);
}

async function expelMember(digest) {
  try {
    await api('/governance/propose-expel', 'POST', { member_digest: digest });
    showToast('Expel proposal created', 'success');
    closeModal();
    loadProposals();
    loadMembers();
  } catch (e) {
    showToast('Expel failed: ' + e.message, 'error');
  }
}

// --- Modals ---
function showModal(contentEl) {
  document.getElementById('modalContent').innerHTML = '';
  document.getElementById('modalContent').appendChild(contentEl);
  document.getElementById('modalOverlay').style.display = 'flex';
}

function closeModal() {
  document.getElementById('modalOverlay').style.display = 'none';
}

function showAddFileModal() {
  const frag = document.createElement('div');

  const title = document.createElement('div');
  title.className = 'modal-title';
  title.textContent = 'Add New File';

  const g1 = document.createElement('div');
  g1.className = 'form-group';
  g1.innerHTML = '<label class="form-label">File path (relative)</label>';
  const pathInput = document.createElement('input');
  pathInput.className = 'form-input';
  pathInput.id = 'newFilePath';
  pathInput.placeholder = 'e.g. contracts/agreement.md';
  g1.appendChild(pathInput);

  const g2 = document.createElement('div');
  g2.className = 'form-group';
  g2.innerHTML = '<label class="form-label">Content</label>';
  const contentArea = document.createElement('textarea');
  contentArea.className = 'editor-textarea';
  contentArea.id = 'newFileContent';
  contentArea.style.minHeight = '200px';
  contentArea.placeholder = '# Document Title\n\nStart writing...';
  g2.appendChild(contentArea);

  const actions = document.createElement('div');
  actions.className = 'modal-actions';

  const btnCancel = document.createElement('button');
  btnCancel.className = 'btn btn-outline';
  btnCancel.textContent = 'Cancel';
  btnCancel.addEventListener('click', closeModal);

  const btnAdd = document.createElement('button');
  btnAdd.className = 'btn btn-primary';
  btnAdd.textContent = 'Add File';
  btnAdd.addEventListener('click', addNewFile);

  actions.append(btnCancel, btnAdd);
  frag.append(title, g1, g2, actions);
  showModal(frag);
}

async function addNewFile() {
  const path = document.getElementById('newFilePath').value.trim();
  const content = document.getElementById('newFileContent').value;
  if (!path) { showToast('File path is required', 'error'); return; }
  try {
    await api('/files/add', 'POST', { path, content });
    showToast('File added locally', 'success');
    closeModal();
    loadFiles();
  } catch (e) {
    showToast('Failed: ' + e.message, 'error');
  }
}

function showExpelMemberModal() {
  const activeMembers = Object.entries(membersByDigest)
    .filter(([d]) => d !== currentNodeDigest);
  if (activeMembers.length === 0) {
    showToast('No other members to expel', 'info');
    return;
  }
  const frag = document.createElement('div');
  const title = document.createElement('div');
  title.className = 'modal-title';
  title.textContent = 'Expel a Member';

  const list = document.createElement('div');
  list.style.margin = '12px 0';
  for (const [digest, name] of activeMembers) {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--light-gray)';
    row.innerHTML = `<span><strong>${escapeHtml(name)}</strong> <small style="opacity:0.5">${escapeHtml(digest.substring(0, 16))}...</small></span>`;
    const btn = document.createElement('button');
    btn.className = 'btn btn-danger btn-sm';
    btn.textContent = 'Expel';
    btn.addEventListener('click', () => {
      closeModal();
      confirmExpelMember(digest, name);
    });
    row.appendChild(btn);
    list.appendChild(row);
  }

  const actions = document.createElement('div');
  actions.className = 'modal-actions';
  const btnCancel = document.createElement('button');
  btnCancel.className = 'btn btn-outline';
  btnCancel.textContent = 'Cancel';
  btnCancel.addEventListener('click', closeModal);
  actions.appendChild(btnCancel);

  frag.append(title, list, actions);
  showModal(frag);
}

function showProposeMemberModal() {
  const frag = document.createElement('div');

  const title = document.createElement('div');
  title.className = 'modal-title';
  title.textContent = 'Propose New Member';

  const g1 = document.createElement('div');
  g1.className = 'form-group';
  g1.innerHTML = '<label class="form-label">Public Key (hex)</label>';
  const keyInput = document.createElement('input');
  keyInput.className = 'form-input';
  keyInput.id = 'newMemberKey';
  keyInput.placeholder = 'ed25519 public key in hex';
  g1.appendChild(keyInput);

  const g2 = document.createElement('div');
  g2.className = 'form-group';
  g2.innerHTML = '<label class="form-label">Display Name (optional)</label>';
  const nameInput = document.createElement('input');
  nameInput.className = 'form-input';
  nameInput.id = 'newMemberName';
  nameInput.placeholder = 'e.g. Alice';
  g2.appendChild(nameInput);

  const actions = document.createElement('div');
  actions.className = 'modal-actions';

  const btnCancel = document.createElement('button');
  btnCancel.className = 'btn btn-outline';
  btnCancel.textContent = 'Cancel';
  btnCancel.addEventListener('click', closeModal);

  const btnPropose = document.createElement('button');
  btnPropose.className = 'btn btn-primary';
  btnPropose.textContent = 'Propose';
  btnPropose.addEventListener('click', proposeMember);

  actions.append(btnCancel, btnPropose);
  frag.append(title, g1, g2, actions);
  showModal(frag);
}

async function proposeMember() {
  const pk = document.getElementById('newMemberKey').value.trim();
  const name = document.getElementById('newMemberName').value.trim();
  if (!pk) { showToast('Public key is required', 'error'); return; }
  try {
    await api('/governance/propose-member', 'POST', {
      public_key_hex: pk,
      display_name: name || null,
    });
    showToast('Member proposal created', 'success');
    closeModal();
    loadProposals(); // refresh proposals so user can vote immediately
  } catch (e) {
    showToast('Failed: ' + e.message, 'error');
  }
}

// --- Event Listeners ---
document.addEventListener('DOMContentLoaded', () => {
  // Navigation
  document.querySelectorAll('.nav-item[data-view]').forEach(el => {
    el.addEventListener('click', () => switchView(el.dataset.view));
  });

  // Proposal filter tabs
  document.querySelectorAll('.tab[data-filter]').forEach(el => {
    el.addEventListener('click', () => filterProposals(el.dataset.filter));
  });

  // Buttons
  document.getElementById('btnNewFile').addEventListener('click', showAddFileModal);
  document.getElementById('btnProposeMember').addEventListener('click', showProposeMemberModal);
  document.getElementById('btnExpelMember').addEventListener('click', showExpelMemberModal);

  // Modal overlay dismiss
  document.getElementById('modalOverlay').addEventListener('click', (e) => {
    if (e.target === document.getElementById('modalOverlay')) closeModal();
  });

  // Prevent modal content clicks from closing
  document.getElementById('modalContent').addEventListener('click', (e) => {
    e.stopPropagation();
  });

  // Sidebar logo fallback
  const logo = document.getElementById('sidebarLogo');
  if (logo) {
    logo.addEventListener('error', () => { logo.parentElement.style.display = 'none'; });
  }
});

// --- Dark Mode ---
const DARK_MODE_KEY = 'quorumtrust-theme';

function getPreferredTheme() {
  const stored = localStorage.getItem(DARK_MODE_KEY);
  if (stored) return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = document.getElementById('darkModeToggle');
  if (btn) {
    btn.textContent = theme === 'dark' ? '☀️' : '🌙';
    btn.title = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
  }
}

function toggleDarkMode() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  localStorage.setItem(DARK_MODE_KEY, next);
}

// Apply saved or system preference on load
applyTheme(getPreferredTheme());

// Toggle button listener
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('darkModeToggle');
  if (btn) {
    btn.addEventListener('click', toggleDarkMode);
  }
});

// --- Init ---
async function init() {
  await loadStatus();
  await loadFiles();
  await loadMembers(); // initial load
  setInterval(loadStatus, 10000);
  setInterval(loadFiles, 5000);
  setInterval(loadMembers, 15000); // auto-update when members accepted/expelled
}

init();
