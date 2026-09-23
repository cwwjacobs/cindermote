// Cindermote SaaS Dashboard Client Logic — Unicode & Live Seam Feed Engine

document.addEventListener('DOMContentLoaded', () => {
  const detonationsTableBody = document.getElementById('detonationsTableBody');
  const seamStreamContainer = document.getElementById('seamStreamContainer');
  const detonationForm = document.getElementById('detonationForm');
  const btnSimulateCollapse = document.getElementById('btnSimulateCollapse');
  
  // Modal elements
  const ashModal = document.getElementById('ashReceiptModal');
  const btnCloseAshModal = document.getElementById('btnCloseAshModal');
  const ashRunId = document.getElementById('ashRunId');
  const ashDispositionChip = document.getElementById('ashDispositionChip');
  const ashKernelHash = document.getElementById('ashKernelHash');
  const ashReplayHash = document.getElementById('ashReplayHash');
  const ashJsonPayload = document.getElementById('ashJsonPayload');
  const btnQuarantineViewer = document.getElementById('btnQuarantineViewer');

  // Initial seam stream log entries
  const initialSeamEvents = [
    { seam: 'guest_mcp_event', source: 'TAINTED_GUEST', target: 'BROKERED_SEAM', hash: 'e3b0c44298fc1c14...', event: 'MCP_INITIALIZED', disp: 'ALLOW' },
    { seam: 'guest_mcp_event', source: 'TAINTED_GUEST', target: 'BROKERED_SEAM', hash: '4eaeb4fce974783c...', event: 'SURFACE_DISCOVERED', disp: 'ALLOW' },
    { seam: 'guest_model_relay', source: 'TAINTED_GUEST', target: 'EXTERNAL_PROVIDER', hash: '8fbfee024ebb72ce...', event: 'MODEL_PROPOSAL_EVAL', disp: 'ALLOW' },
  ];

  let detonations = [
    {
      runId: 'run-8f585828',
      identity: 'npm://@untrusted/mcp-server-tools',
      toolsCount: 2,
      terminalKind: 'NORMAL',
      disposition: 'ADMIT',
      cues: [],
      kernelHash: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      replayHash: 'sha256:4eaeb4fce974783cd3bcd4fe30afa15e001f8f4f160073b33825396364c99dd2'
    },
    {
      runId: 'run-3a91b2c4',
      identity: 'npm://@malicious/host-access-probe',
      toolsCount: 1,
      terminalKind: 'COLLAPSE',
      disposition: 'DENY',
      cues: ['host_path_access'],
      kernelHash: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      replayHash: 'sha256:e069a760745aa9580a16b2fa745af368eb90d525a5c3a09cd675aef8f97dad30'
    }
  ];

  function renderSeamStream() {
    seamStreamContainer.innerHTML = '';
    initialSeamEvents.forEach(ev => {
      appendSeamLine(ev);
    });
  }

  function appendSeamLine(ev) {
    const div = document.createElement('div');
    const isCollapse = ev.disp === 'COLLAPSE' || ev.disp === 'DENY';
    div.className = `seam-event-line ${isCollapse ? 'collapse-event' : ''}`;
    
    div.innerHTML = `
      <div>
        <span class="seam-tag">[${ev.seam}]</span>
        <strong>${ev.event}</strong>
        <span style="font-size: 10px; color: var(--text-muted); margin-left: 8px;">${ev.source} ⯈ ${ev.target}</span>
      </div>
      <div>
        <span class="seam-hash">${ev.hash}</span>
        <span class="disp-badge ${isCollapse ? 'disp-deny' : 'disp-admit'}" style="margin-left: 10px;">${ev.disp}</span>
      </div>
    `;
    seamStreamContainer.prepend(div);
  }

  function renderTable() {
    detonationsTableBody.innerHTML = '';
    detonations.forEach((item) => {
      const tr = document.createElement('tr');
      const dispClass = item.disposition === 'ADMIT' ? 'disp-admit' : item.disposition === 'DENY' ? 'disp-deny' : 'disp-restrict';
      
      tr.innerHTML = `
        <td><code style="color: var(--accent-primary);">${item.runId}</code></td>
        <td><code>${item.identity}</code></td>
        <td>${item.toolsCount} Tools | SHA-256 Hashed</td>
        <td><span style="font-weight: 600;">${item.terminalKind}</span></td>
        <td><span class="disp-badge ${dispClass}">${item.disposition}</span></td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="viewAshReceipt('${item.runId}')" style="padding: 4px 10px; font-size: 11px;">
            <span class="unicode-icon text-amber">⌬</span> Ash Receipt
          </button>
        </td>
      `;
      detonationsTableBody.appendChild(tr);
    });
  }

  window.viewAshReceipt = function(runId) {
    const item = detonations.find(d => d.runId === runId);
    if (!item) return;

    ashRunId.textContent = item.runId;
    ashDispositionChip.textContent = item.disposition;
    ashDispositionChip.className = `ash-status-chip ${item.disposition === 'ADMIT' ? 'disp-admit' : 'disp-deny'}`;
    ashKernelHash.textContent = item.kernelHash.substring(0, 32) + '...';
    ashReplayHash.textContent = item.replayHash.substring(0, 32) + '...';

    const boundedPayload = {
      receipt_version: "cindermote-ash/v1",
      run_id: item.runId,
      target_identity: item.identity,
      provenance: {
        frozen_base_repo: "motefield (private predecessor)",
        frozen_base_commit: "584ab11ea054efb233d057b64c342846ed201592"
      },
      discovered_surface_counts: { tools: item.toolsCount, prompts: 0, resources: 0 },
      terminal_kind: item.terminalKind,
      purge_verification_results: { cgroup_removed: true, netns_removed: true, process_reaped: true, ram_jail_deleted: true },
      final_disposition: item.disposition,
      deterministic_cues: item.cues,
      authentication_metadata: {
        algorithm: "PBKDF2-HMAC-SHA256",
        signature_hmac: "d594cb95450faeb9bcd3a0799d2643431721cbe64c4b8e04d9fa2fcf58d4b18f"
      }
    };

    ashJsonPayload.textContent = JSON.stringify(boundedPayload, null, 2);
    ashModal.style.display = 'flex';
  };

  btnCloseAshModal.addEventListener('click', () => {
    ashModal.style.display = 'none';
  });

  btnQuarantineViewer.addEventListener('click', () => {
    alert("🔐 Quarantined Viewer: Local encrypted replay cipher decrypted under isolated viewer context.");
  });

  detonationForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const uri = document.getElementById('targetPackageUri').value;
    const newRunId = `run-${Math.random().toString(16).substring(2, 10)}`;

    const newDetonation = {
      runId: newRunId,
      identity: uri,
      toolsCount: Math.floor(Math.random() * 5) + 1,
      terminalKind: 'NORMAL',
      disposition: 'ADMIT',
      cues: [],
      kernelHash: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      replayHash: `sha256:${Math.random().toString(16).substring(2, 34)}`
    };

    detonations.unshift(newDetonation);
    renderTable();

    // Stream live seam events
    appendSeamLine({
      seam: 'guest_mcp_event',
      source: 'TAINTED_GUEST',
      target: 'BROKERED_SEAM',
      hash: `sha256:${Math.random().toString(16).substring(2, 18)}...`,
      event: 'TOOL_INVOKED',
      disp: 'ALLOW'
    });

    document.getElementById('kpiActiveKernels').textContent = parseInt(document.getElementById('kpiActiveKernels').textContent) + 1;
    document.getElementById('kpiSurfacesCount').textContent = parseInt(document.getElementById('kpiSurfacesCount').textContent) + newDetonation.toolsCount;
  });

  btnSimulateCollapse.addEventListener('click', () => {
    const newRunId = `run-${Math.random().toString(16).substring(2, 10)}`;
    const newDetonation = {
      runId: newRunId,
      identity: 'npm://@hostile/unauthorized-path-probe',
      toolsCount: 1,
      terminalKind: 'COLLAPSE',
      disposition: 'DENY',
      cues: ['host_path_access'],
      kernelHash: 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      replayHash: `sha256:${Math.random().toString(16).substring(2, 34)}`
    };

    detonations.unshift(newDetonation);
    renderTable();

    // Stream collapse seam event
    appendSeamLine({
      seam: 'host_collapse_signal',
      source: 'TRUSTED_HOST',
      target: 'TAINTED_GUEST',
      hash: `cue:host_path_access`,
      event: 'KERNEL_COLLAPSE_TRIGGERED',
      disp: 'COLLAPSE'
    });

    document.getElementById('kpiCollapseCount').textContent = parseInt(document.getElementById('kpiCollapseCount').textContent) + 1;
  });

  renderSeamStream();
  renderTable();
});
