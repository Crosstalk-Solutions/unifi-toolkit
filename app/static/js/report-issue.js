/* Shared "Report an issue" footer link for the tool pages.
 *
 * Attaches to any element carrying data-report-issue. On click it fetches
 * /api/debug-info and opens a pre-filled GitHub issue, the same flow the
 * dashboard footer has; data-tool (e.g. "House Arrest") prefixes the issue
 * title so triage can see which tool without reading the body. If anything
 * fails, the link still lands on a usable new-issue page rather than dying.
 */
(function () {
    'use strict';

    var REPO = 'https://github.com/Crosstalk-Solutions/unifi-toolkit';

    function buildTemplate() {
        return '## Description\n' +
            "<!-- Please describe the issue you're experiencing -->\n\n\n" +
            '## Steps to Reproduce\n' +
            '<!-- What steps lead to the issue? -->\n1.\n2.\n3.\n\n' +
            '## Expected Behavior\n' +
            '<!-- What did you expect to happen? -->\n\n\n' +
            '## Actual Behavior\n' +
            '<!-- What actually happened? -->\n\n\n' +
            '## Environment\n';
    }

    async function buildBody() {
        var body = buildTemplate();
        try {
            var response = await fetch('/api/debug-info');
            var info = await response.json();

            body += '- **App Version:** ' + info.app_version + '\n';
            body += '- **Tool Versions:**\n';
            var tools = info.tool_versions || {};
            Object.keys(tools).forEach(function (key) {
                body += '  - ' + key + ': ' + tools[key] + '\n';
            });

            var dep = info.deployment || {};
            body += '- **Deployment:**\n';
            body += '  - Type: ' + dep.type + '\n';
            body += '  - Docker: ' + (dep.docker ? 'Yes' : 'No') + '\n';
            body += '  - Python: ' + dep.python_version + '\n';

            var gw = info.gateway || {};
            if (gw.model) {
                body += '- **Gateway:**\n';
                body += '  - Model: ' + gw.model + (gw.name ? ' (' + gw.name + ')' : '') + '\n';
                if (gw.firmware) body += '  - Firmware: ' + gw.firmware + '\n';
                body += '  - UniFi OS: ' + (gw.is_unifi_os ? 'Yes' : 'No') + '\n';
            } else {
                body += '- **Gateway:** Not configured or not connected\n';
            }
        } catch (e) {
            body += '- _(Could not fetch debug info; please paste it from the dashboard footer)_\n';
        }
        body += '- **Browser:** ' + navigator.userAgent + '\n';
        return body;
    }

    document.querySelectorAll('[data-report-issue]').forEach(function (link) {
        link.addEventListener('click', async function (e) {
            e.preventDefault();
            var tool = link.getAttribute('data-tool') || '';
            var url;
            try {
                url = REPO + '/issues/new?' + new URLSearchParams({
                    title: tool ? '[' + tool + '] ' : '',
                    body: await buildBody(),
                    labels: 'bug'
                }).toString();
            } catch (err) {
                url = REPO + '/issues/new';
            }
            window.open(url, '_blank', 'noopener');
        });
    });
})();
