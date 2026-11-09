(function () {
    const input = document.getElementById('key');
    if (!input) return;
    const pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const hint = document.getElementById('keyHint');
    input.addEventListener('input', function () {
        const value = input.value.trim();
        const valid = pattern.test(value);
        const show = value.length > 0 && !valid;
        input.classList.toggle('invalid', show);
        hint.className = 'hint' + (show ? ' bad' : valid ? ' good' : '');
        hint.textContent = show ? 'A full key has 36 characters with dashes.' : valid ? 'Key format looks right.' : '';
    });
})();

(function () {
    if (!document.getElementById('copyKey')) return;
    const copyBtn = document.getElementById('copyKey');
    const key = copyBtn.dataset.key;
    const downloadBtn = document.getElementById('downloadKey');
    const saved = document.getElementById('savedCheck');
    const next = document.getElementById('continueBtn');

    copyBtn.addEventListener('click', async function () {
        try {
            await navigator.clipboard.writeText(key);
            copyBtn.textContent = 'Copied';
        } catch (e) {
            const range = document.createRange();
            range.selectNodeContents(document.querySelector('.key-segments'));
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
            copyBtn.textContent = 'Press copy on your device';
        }
    });

    downloadBtn.addEventListener('click', function () {
        const blob = new Blob(['Stowkey access key\n\n' + key + '\n'], { type: 'text/plain' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'stowkey-key.txt';
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(link.href); }, 1000);
        downloadBtn.textContent = 'Downloaded';
    });

    saved.addEventListener('change', function () { next.disabled = !saved.checked; });
    next.disabled = !saved.checked;
})();

(function () {
    const toast = document.querySelector('.toast');
    if (toast) setTimeout(function () { toast.remove(); }, toast.querySelector('form') ? 10000 : 5000);

    document.querySelectorAll('.confirm-form').forEach(function (form) {
        form.addEventListener('submit', function (event) {
            const button = form.querySelector('button');
            if (button.classList.contains('armed')) return;
            event.preventDefault();
            button.classList.add('armed');
            button.textContent = 'Yes, delete forever';
            setTimeout(function () {
                button.classList.remove('armed');
                button.textContent = 'Delete forever';
            }, 5000);
        });
    });

    const zone = document.getElementById('dropZone');
    if (zone) {
        const input = document.getElementById('fileInput');
        const pick = document.getElementById('pickBtn');
        const progress = document.getElementById('progress');
        const bar = document.getElementById('progressBar');
        const label = document.getElementById('progressLabel');
        const pct = document.getElementById('progressPct');
        const error = document.getElementById('uploadError');
        let busy = false;

        function finish(message) {
            busy = false;
            pick.disabled = false;
            progress.hidden = true;
            error.textContent = message;
            input.value = '';
        }

        function upload(files) {
            if (busy || files.length === 0) return;
            busy = true;
            pick.disabled = true;
            error.textContent = '';
            const data = new FormData();
            for (const file of files) data.append('file_upload[]', file);
            data.append('csrf', document.getElementById('csrfToken').value);
            data.append('action', 'upload');
            label.textContent = files.length === 1 ? 'Encrypting and uploading ' + files[0].name : 'Encrypting and uploading ' + files.length + ' files';
            bar.value = 0;
            pct.textContent = '0%';
            progress.hidden = false;

            const request = new XMLHttpRequest();
            request.open('POST', 'dashboard.php');
            request.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            request.upload.onprogress = function (event) {
                if (!event.lengthComputable) return;
                const value = Math.round(event.loaded / event.total * 100);
                bar.value = value;
                pct.textContent = value + '%';
            };
            request.onload = function () {
                let result = {};
                try { result = JSON.parse(request.responseText); } catch (e) {}
                if (result.ok || result.saved > 0) {
                    window.location.reload();
                    return;
                }
                finish((result.errors || []).map(function (item) { return item.message; }).join('\n') || 'Upload failed. Please try again.');
            };
            request.onerror = function () { finish('Upload failed. Check your connection and try again.'); };
            request.send(data);
        }

        pick.addEventListener('click', function () { input.click(); });
        input.addEventListener('change', function () { upload(input.files); });
        ['dragenter', 'dragover'].forEach(function (name) {
            zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.add('over'); });
        });
        ['dragleave', 'drop'].forEach(function (name) {
            zone.addEventListener(name, function (event) { event.preventDefault(); zone.classList.remove('over'); });
        });
        zone.addEventListener('drop', function (event) { upload(event.dataTransfer.files); });
    }
})();
