let app = {

    hibpCache: new Map(),
    worstCache: new Map(),

    chartInstance: null,

    elements: {
        pwd: document.getElementById('pwd'),
        toggle: document.getElementById('toggle'),
        charTable: document.getElementById('charTable'),
        totalChars: document.getElementById('totalChars'),
        bits: document.getElementById('bits'),
        verdict: document.getElementById('verdict'),
        why: document.getElementById('why'),
        exposureListTable: document.getElementById('exposureListTable'),
        length: document.getElementById('length'),
        lengthVerdict: document.getElementById('lengthVerdict'),
        lengthWhy: document.getElementById('lengthWhy'),
        suggestions: document.getElementById('suggestions'),
        radarCanvas: document.getElementById('passwordRadar'),
        canvasContainer: document.getElementById('containerCanvas'),
    },

    charsets: {
        lower: { label: 'Lowercase Letters', size: 26, regex: /[a-z]/ },
        upper: { label: 'Uppercase Letters', size: 26, regex: /[A-Z]/ },
        digit: { label: 'Numbers', size: 10, regex: /[0-9]/ },
        symbol: { label: 'Symbols', size: 33, regex: /[!@#$%^&*()`~\-_=+\[\]{};:'"\\|,.<>/?]/ },
        space: { label: 'Space', size: 1, regex: /[\s]/ },
        // other: { label: 'Other Symbols', size: 100 }
    },

    debounce(fn, delay = 300) {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => fn(...args), delay);
        };
    },

    resizeCanvas() {
        this.render(this.elements.pwd.value);
    },

    async init() {
        this.elements.toggle.addEventListener('click', () => {
            const isPwd = this.elements.pwd.type === 'password';
            this.elements.pwd.type = isPwd ? 'text' : 'password';
            this.elements.toggle.textContent = isPwd ? 'hide' : 'show';
            this.elements.pwd.focus();
        });

        this.elements.pwd.addEventListener('input', this.debounce(e => this.render(e.target.value)));

        window.addEventListener("resize", this.resizeCanvas.bind(this));

        await this.render('');
    },

    async sha1(input) {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        return [...new Uint8Array(hashBuffer)]
            .map(b => b.toString(16).padStart(2, '0'))
            .join('')
            .toUpperCase();
    },

    async hibpCheck(password) {
        const hash = await this.sha1(password);

        if (this.hibpCache.has(hash))
            return this.hibpCache.get(hash);

        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);

        const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        if (!res.ok) throw new Error(`HIBP request failed: ${res.status}`);

        const body = await res.text();

        let result = { found: false, breachCount: 0 };

        for (const line of body.split('\n')) {
            const [lineSuffix, countStr] = line.split(':');
            if (lineSuffix === suffix) {
                result = { found: true, breachCount: parseInt(countStr, 10) };
                break;
            }
        }

        this.hibpCache.set(hash, result);

        return result;
    },

    zxcvbnCheck(password) {
        if (typeof zxcvbn !== 'function')
            throw new Error('zxcvbn is not loaded or available.');

        const result = zxcvbn(password);

        return {
            crack_display: result.crack_times_display.offline_slow_hashing_1e4_per_second,
            crack_seconds: result.crack_times_seconds.offline_slow_hashing_1e4_per_second,
            guesses: result.guesses,
            guesses_log10: result.guesses_log10,
            score: result.score,
            feedback: {
                warning: result.feedback?.warning || '',
                suggestions: result.feedback?.suggestions || []
            },
            sequence: result.sequence,
            calc_time_ms: result.calc_time
        }
    },

    calculatePasswordStrength(password) {
        const charsetsUsed = new Set();
        let totalCharacters = 0;

        for (const charset of Object.keys(this.charsets)) {
            if (password.match(this.charsets[charset].regex)) {
                charsetsUsed.add(this.charsets[charset].label)
                totalCharacters += this.charsets[charset].size || 0;
            }
        }

        const entropy = Math.floor(password.length * Math.log2(totalCharacters || 1)); // avoid log2(0)

        // Map entropy to strength and explanation
        let strength, explanation, score;

        if (entropy < 28) {
            score = 0;
            strength = "Very Weak";
            explanation = "Easily guessable, avoid using common words or short passwords.";
        } else if (entropy < 36) {
            score = 1;
            strength = "Weak";
            explanation = "May survive a few guesses, but still easy to crack.";
        } else if (entropy < 60) {
            score = 2;
            strength = "Moderate";
            explanation = "Decent for online accounts with rate-limiting, but could be cracked offline.";
        } else if (entropy < 80) {
            score = 3;
            strength = "Strong";
            explanation = "Suitable for most situations.";
        } else if (entropy < 128) {
            score = 4;
            strength = "Very Strong";
            explanation = "Highly resistant to cracking attempts.";
        } else {
            score = 5;
            strength = "Extremely Strong";
            explanation = "Suitable for master passwords or encryption keys.";
        }

        return {
            score,
            entropy,
            strength,
            explanation,
            meetsComplexityPolicy: charsetsUsed.size >= 3 && password.length >= 8,
            charsetsUsed,
            totalCharacters
        };
    },

    async fetchList(url, type) {
        try {
            if (this.worstCache.has(url))
                return this.worstCache.get(url);

            const res = await fetch(url);
            if (!res.ok) throw new Error(`Fetch list failed: ${res.status}`);

            const content = type === 'json'
                ? await res.json()
                : await res.text();

            this.worstCache.set(url, content);

            return content;
        } catch (ex) {
            console.error(`Failed to fetch list - ${url}`, ex);
        }

        return type === 'json' ? [] : '';
    },

    async checkWorstPasswords(password) {
        const lists = [
            {
                url: '/nord-pass-worst-password-list-2024-b2b-au.json', // https://nordpass.com/next/worst-passwords-list/2024/b2b/au.json
                category: 'NordPass Business Passwords',
                type: 'json'
            },
            {
                url: '/nord-pass-worst-password-list-2024-b2c-au.json', // https://nordpass.com/next/worst-passwords-list/2024/b2c/au.json
                category: 'NordPass Consumer Passwords',
                type: 'json'
            },
            {
                url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt',
                category: 'Most Used Passwords',
                type: 'txt'
            }
        ];

        for (const { url, type } of lists) {
            const data = await this.fetchList(url, type);

            if (type === 'json') {
                if (data.some(entry => entry.Password === password))
                    return true;
            } else {
                if (data.split('\n').some(line => line.trim() === password))
                    return true;
            }
        }

        return false;
    },

    async check(password) {
        const [worst, hibp] = await Promise.all([
            this.checkWorstPasswords(password),
            this.hibpCheck(password)
        ]);

        const strength = this.calculatePasswordStrength(password);
        const zxcvbn = this.zxcvbnCheck(password);

        const result = { password, worst, hibp, strength, zxcvbn };

        this.renderRadarChart(result);

        return result;
    },

    renderRadarChart({ password, worst, hibp, strength, zxcvbn }) {
        const RECOMMENDED_PASSWORD_LENGTH = 14;
        const MAX_STRENGTH_SCORE = 5;
        const MAX_ZXCVBN_SCORE = 4;
        const MIN_CHARSETS_REQUIRED = 3;

        const metrics = {
            Length: Math.min(password.length, RECOMMENDED_PASSWORD_LENGTH) / RECOMMENDED_PASSWORD_LENGTH * 100,
            Randomness: (strength.score / MAX_STRENGTH_SCORE) * 100,
            'Hard to Guess': (zxcvbn.score / MAX_ZXCVBN_SCORE) * 100,
            'Never Seen in Data Breaches': hibp.found ? 0 : 100,
            'Not a Common Password': worst ? 0 : 100,
            'Variety of Character Types': Math.min(strength.charsetsUsed.size, MIN_CHARSETS_REQUIRED) / MIN_CHARSETS_REQUIRED * 100
        };

        const ctx = document.getElementById('passwordRadar').getContext('2d');

        if (this.chartInstance)
            this.chartInstance.destroy();

        this.chartInstance = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: Object.keys(metrics),
                datasets: [{
                    label: 'Password Strength',
                    data: Object.values(metrics),
                    backgroundColor: "rgba(0, 153, 255, 0.2)",
                    borderColor: "rgba(0, 153, 255, 1)",
                    pointBackgroundColor: "#00ccff",
                    pointBorderColor: "#fff"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        min: 0,
                        max: 100,
                        ticks: { display: false },
                        angleLines: { color: "#444" },
                        grid: { circular: false, color: "#333" },
                        pointLabels: { color: "#fff", padding: 20, font: { size: 14, weight: 800 } },
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    },

    updateCharsetTable(strength) {
        this.elements.charTable.innerHTML = Object.entries(this.charsets)
            .map(([_, { label, size }]) => {
                const used = strength.charsetsUsed.has(label);
                const icon = used ? '✅' : '❌';
                return `
                    <tr>
                        <td class="icon">${icon}</td>
                        <td>${label}</td>
                        <td>${size} chars</td>
                    </tr>`;
            })
            .join('')
            ;
        this.elements.totalChars.textContent = `Total possible characters: ${strength.totalCharacters}`;
    },

    updateExposureList(password, worst, hibp) {
        const checks = [
            { found: worst, label: "on Common Password lists", none: "Common Password lists" },
            { found: hibp.found, label: "in previous Data Breaches", none: "previous Data Breaches" }
        ];

        this.elements.exposureListTable.innerHTML = checks
            .map(({ found, label, none }) => {
                if (!password) {
                    return `<tr>
                        <td class="icon">⚠️</td>
                        <td class="warn">Unable to check ${none}</td>
                    </tr>`;
                }
                const safe = !found;
                const icon = safe ? '✅' : '🚨';
                const prefix = safe ? 'Not found' : 'Found';
                const cls = safe ? 'ok' : 'bad';
                return `
                    <tr>
                        <td class="icon">${icon}</td>
                        <td class="${cls}">${prefix} ${label}</td>
                    </tr>`;
            })
            .join('')
            ;
    },

    updateLengthVerdict(length) {
        this.elements.length.textContent = `${length} Character${length === 1 ? '' : 's'}`;

        let verdict, reason, cls;

        if (length === 0)
            [verdict, reason, cls] = ["None", "No password entered", "bad"];
        else if (length < 5)
            [verdict, reason, cls] = ["Very Weak", "Far too short", "bad"];
        else if (length < 8)
            [verdict, reason, cls] = ["Weak", "Easy to guess", "bad"];
        else if (length < 11)
            [verdict, reason, cls] = ["Moderate", "Minimum recommended", "warn"];
        else if (length < 14)
            [verdict, reason, cls] = ["Strong", "Harder to crack", "ok"];
        else
            [verdict, reason, cls] = ["Excellent", "Very hard to guess", "ok"];
        
        this.elements.lengthVerdict.textContent = verdict;
        this.elements.lengthWhy.textContent = reason;
        this.elements.lengthVerdict.className = cls;
        this.elements.length.className = cls;
    },

    updateStrengthVerdict(length, strength) {
        const { entropy, explanation } = strength;
        const cls = entropy < 36 ? 'bad' : entropy < 60 ? 'warn' : 'ok';

        this.elements.verdict.textContent = strength.strength;
        this.elements.verdict.className = cls;
        this.elements.bits.textContent = `~${entropy} Bits`;
        this.elements.bits.className = `bits ${cls}`;
        this.elements.why.textContent = length > 0 ? explanation : "No password entered";
    },

    updateSuggestions(password, worst, hibp, strength, zxcvbn) {
        if (!password) {
            this.elements.suggestions.innerHTML = `<p class="muted">Enter a password to generate suggestions</p>`;
            return;
        }

        const suggestions = [];

        if (hibp.found) {
            suggestions.push(
                `<li class="bad">Avoid using passwords that have been exposed online, even if they seem strong. Choose a unique password that hasn't been leaked</li>`,
                `<ul><li style="font-weight: 700">This password is no longer safe!</li><li>Please make sure to change this password on all platforms where it is used to keep your accounts secure</li></ul>`
            );
        }

        if (worst) {
            suggestions.push(`<li class="bad">Choose a less predictable password. Avoid simple or popular phrases like "password123" or "qwerty" - they are the first to be guessed in attacks</li>`);
            if (!hibp.found) {
                suggestions.push(`<ul><li style="font-weight: 700">This password is not recommended.</li><li>Please make sure to change this password on all platforms where it is used to keep your accounts secure</li></ul>`);
            }
        }

        if (zxcvbn.feedback.warning) {
            suggestions.push(`<li class="warn">${zxcvbn.feedback.warning}</li>`);
        }

        if (!strength.meetsComplexityPolicy) {
            suggestions.push(`<li class="warn">This password doesn't meet common complexity requirements, try including a mix of letters, numbers, and symbols</li>`);
        }

        suggestions.push(...zxcvbn.feedback.suggestions.map(s => `<li>${s}</li>`));

        this.elements.suggestions.innerHTML = suggestions.length > 0 ?
            `<ul>${suggestions.join('')}</ul>` : 
            `<p class="ok">No suggestions - well done!</p>`;
    },


    async render(password) {
        const [worst, hibp] = await Promise.all([
            this.checkWorstPasswords(password),
            this.hibpCheck(password)
        ]);

        const strength = this.calculatePasswordStrength(password);
        const zxcvbn = this.zxcvbnCheck(password);

        this.updateCharsetTable(strength);
        this.updateExposureList(password, worst, hibp);
        this.updateLengthVerdict(password.length);
        this.updateStrengthVerdict(password.length, strength);
        this.updateSuggestions(password, worst, hibp, strength, zxcvbn);

        this.renderRadarChart({ password, worst, hibp, strength, zxcvbn });
    }
};

app.init();