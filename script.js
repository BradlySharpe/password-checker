const THREE_HOURS = 10800; // 3 * 60 * 60
const TWELVE_DAYS = 1036800; // 12 * 24 * 60 * 60

START_UPPER = /^[A-Z][^A-Z]+$/
ALL_UPPER = /^[^a-z]+$/

let app = {

    hibpCache: new Map(),
    worstCache: new Map(),

    chartInstance: null,

    elements: {
        valueToCheck: document.getElementById('valueToCheck'),
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
        crackTimeVerdict: document.getElementById('crackTimeVerdict'),
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
        other: { label: 'Other Characters', size: 100 }
    },

    debounce(fn, delay = 300) {
        let timeout;
        return (...args) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => fn(...args), delay);
        };
    },

    resizeCanvas() {
        this.render(this.elements.valueToCheck.value);
    },

    getPasswordLength(password) {
        // Fix: Most unicode characters count as 2 using .length on the string

        if (typeof Intl?.Segmenter === 'function') {
            const segmenter = new Intl.Segmenter(navigator.language || 'en', { granularity: 'grapheme' });
            return [...segmenter.segment(password)].length;
        }

        // Fallback: Unicode code points (still better than .length)
        return [...password].length;
    },

    async init() {
        this.elements.toggle.addEventListener('click', () => {
            const isPwd = this.elements.valueToCheck.className === 'masked';
            this.elements.valueToCheck.className = isPwd ? '' : 'masked';
            this.elements.toggle.textContent = isPwd ? 'hide' : 'show';
            this.elements.valueToCheck.focus();
        });

        this.elements.valueToCheck.addEventListener('input', this.debounce(e => this.render(e.target.value)));

        window.addEventListener("resize", this.resizeCanvas.bind(this));

        const combinedCharsetRegexes = Object.values(app.charsets)
            .filter(c => c.regex instanceof RegExp)
            .map(c => {
                const src = c.regex.source;
                if (src.startsWith('[') && src.endsWith(']'))
                    return src.slice(1, -1); // remove the square brackets - Assumes all regex follow /[ ... ]/ pattern

                return '';
            });

        app.charsets.other.regex = new RegExp(`[^${combinedCharsetRegexes.join('')}]`, 'u');

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
        if (!password || password.length <= 0)
            return { found: true, breachCount: 0 };

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
            if (this.charsets[charset].regex) {
                if (this.charsets[charset].regex.test(password)) {
                    charsetsUsed.add(this.charsets[charset].label)
                    totalCharacters += this.charsets[charset].size || 0;
                }
            }
        }

        const passwordLength = this.getPasswordLength(password);

        const entropy = Math.floor(passwordLength * Math.log2(totalCharacters || 1)); // avoid log2(0)

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
            meetsComplexityPolicy: charsetsUsed.size >= 3 && passwordLength >= 8,
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
        if (!password || password.length <= 0)
            return true;

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

        const passwordLength = this.getPasswordLength(password);

        const metrics = {
            Length: Math.min(passwordLength, RECOMMENDED_PASSWORD_LENGTH) / RECOMMENDED_PASSWORD_LENGTH * 100,
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
            .map(([key, { label, size }]) => {
                const used = strength.charsetsUsed.has(label);
                const icon = used ? '✅' : '❌';
                const sizePrefix = key === "other" ? "~" : "";
                return `
                    <tr>
                        <td class="icon">${icon}</td>
                        <td>${label}</td>
                        <td>${sizePrefix}${size} chars</td>
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

    capitalizeFirstLetter(val) {
        return String(val).charAt(0).toUpperCase() + String(val).slice(1);
    },

    updateTimeToCrack(hibp, worst, length, zxcvbn) {
        if (length <= 0) {
            this.elements.crackTimeVerdict.textContent = "No password entered";
            this.elements.crackTimeVerdict.className = 'muted';
            return;
        }

        if (zxcvbn.crack_seconds < THREE_HOURS)
            this.elements.crackTimeVerdict.className = 'bad';
        else if (zxcvbn.crack_seconds < TWELVE_DAYS)
            this.elements.crackTimeVerdict.className = 'warn';
        else
            this.elements.crackTimeVerdict.className = 'ok';

        let message = zxcvbn.crack_display;

        if (hibp.found || worst)
            message = "Instantly";

        if (/^[0-9]/.test(message))
            message = `~${message}`;

        this.elements.crackTimeVerdict.textContent = this.capitalizeFirstLetter(message);
    },

    hasRecentYear(password) {
        // Include years past 201x
        const recent_year = /19\d\d|20[0-5]\d/;
        return recent_year.test(password);
    },

    checkSequences(zxcvbn, password) {
        let hasRecentYear = false;

        const addedPatterns = new Set();
        const errors = new Set();
        const warnings = new Set();
        const information = new Set();

        const isSoloMatch = zxcvbn.sequence.length === 1;

        for (let seq of zxcvbn.sequence) {
            if (addedPatterns.has(seq.pattern))
                continue;

            let prefix;

            switch (seq.pattern) {
                case 'dictionary':
                    hasDictionaryWords = true;
                    const word = seq.token;

                    if (seq.dictionary_name == 'passwords') {

                        if (isSoloMatch && !seq.l33t && !seq.reversed) {
                            if (seq.rank <= 10)
                                errors.add('This is a top-10 common password');
                            else if (seq.rank <= 100)
                                errors.add('This is a top-100 common password');
                            else
                                errors.add('This is a very common password');
                        }
                        // else if (seq.guesses_log10 <= 4)
                        //     warnings.add('This is similar to a commonly used password');

                        /* if (word.match(START_UPPER))
                            information.add("Capitalisation doesn't help very much");
                        else */ if (word.match(ALL_UPPER) && word.toLowerCase() != word)
                            information.add("Using only capital letters isn't much safer than using only lowercase, mix both for better security");

                        if (seq.reversed && seq.token.length >= 4)
                            information.add("Writing a word backwards doesn't make it much harder to guess")
                        
                        if (seq.l33t)
                            information.add("Predictable substitutions like '@' instead of 'a' don't help very much");
                    } else if (seq.dictionary_name == 'english_wikipedia') {
                        if (isSoloMatch)
                            errors.add('One word on its own is too easy to guess');
                    } else if (['surnames', 'male_names', 'female_names'].includes(seq.dictionary_name)) {
                        if (isSoloMatch)
                            errors.add('Names (like your first or last name) make weak passwords');
                        else
                            warnings.add(`Common names and surnames, such as ${seq.token.toLowerCase()}, are easy to guess`);
                    }
                    
                    break;

                case 'spatial':
                    if (seq.graph == 'dvorak') // Ignore dvorak patterns as they are less likely
                        continue;

                    if (seq.graph == 'keypad' && this.hasRecentYear(password)) // Skip to add warning about date instead
                        continue

                    if (seq.turns == 1)
                        warnings.add('Typing straight rows on the keyboard, like "asdfgh", is easy to guess. If using patterns, make them long and unpredictable');
                    else
                        warnings.add('Typing easy patterns like "qwerty" or "asdf" makes your password predictable. Try mixing in different letters, numbers, and symbols instead');

                    addedPatterns.add(seq.pattern);

                    break;

                case 'repeat':
                    if (seq.base_token.length == 1)
                        warnings.add(`Repeats like "aaa" are easy to guess, avoid repeated words and characters`);
                    else
                        warnings.add(`Repeats like "abcabcabc" are only slightly harder to guess than "abc", avoid repeated words and characters`);
                    addedPatterns.add(seq.pattern);
                    break;

                case 'sequence':
                    warnings.add(`Simple number or letter sequences (like 1234 or abcd) are very easy to guess, try to avoid these`);
                    addedPatterns.add(seq.pattern);
                    break;

                case 'regex':
                    if (zxcvbn.sequence.some(s => s.pattern == 'date'))
                        break;
                    if (seq.regex_name == 'recent_year') {
                        warnings.add(`Recent years (like 2023) are common in passwords. Especially avoid years that are connected to you, such as birthdays, anniversaries, or other personal dates.`);
                        hasRecentYear = true;
                        addedPatterns.add(seq.pattern);
                    }
                    break;

                case 'date':
                    warnings.add(`Dates are often easy to guess, avoid dates and years that are associated with you such as birthdays, anniversaries, or other personal dates`);
                    addedPatterns.add(seq.pattern);
                    break;
            
                default:
                    break;
            }
        }

        if (!hasRecentYear && this.hasRecentYear(password) && !zxcvbn.sequence.some(s => s.pattern == 'date'))
            warnings.add(`Recent years, like 2024, are common in passwords. Especially avoid years that are connected to you, such as birthdays, anniversaries, or other personal dates.`);

        if (/^[A-Z][^A-Z]*$/.test(password))
            warnings.add('Most passwords start with a capital and is an easy pattern to guess');

        if (/[^\d]\d+$/.test(password))
            warnings.add('Predictable patterns like trailing numbers make your password easier to crack');

        if (/[^!@#$%^&*()`~\-_=+\[\]{};:'"\\|,.<>/?][!@#$%^&*()`~\-_=+\[\]{};:'"\\|,.<>/?]+$/.test(password))
            warnings.add(`Symbols are helpful, but placing them at the end is predictable`);

        return {
            errors: Array.from(errors),
            warnings: Array.from(warnings),
            information: Array.from(information),
            sequences: zxcvbn.sequence
        };
    },

    updateSuggestions(password, worst, hibp, strength, zxcvbn) {
        if (!password) {
            this.elements.suggestions.innerHTML = `<p class="muted">Enter a password to generate suggestions</p>`;
            return;
        }

        let listItemsHtml = '';

        if (hibp.found) {
            listItemsHtml += `
                <li class="bad">This password is no longer safe!</li>
                <ul>
                    <li>Please make sure to change this password on all platforms where it is used to keep your accounts secure</li>
                    <li>Avoid using passwords that have been exposed online, even if they seem strong. Choose a unique password that hasn't been leaked</li>
                </ul>`;
        }

        if (worst) {
            listItemsHtml += `<li class="bad">This password is found on common password lists and is not recommended</li>`;

            if (!hibp.found)
                listItemsHtml += `
                <ul>
                    <li>Please make sure to change this password on all platforms where it is used to keep your accounts secure</li>
                    <li>Choose a less predictable password. Avoid simple or popular phrases like "password123" or "qwerty" - they are the first to be guessed in attacks</li>
                </ul>`;
        }

        if (zxcvbn.crack_seconds < THREE_HOURS)
            listItemsHtml += `<li class="bad">This password is is far too simple and offers almost no protection</li>`;

        const suggestions = this.checkSequences(zxcvbn, password);

        if (zxcvbn.crack_seconds >= THREE_HOURS && zxcvbn.crack_seconds < TWELVE_DAYS)
            suggestions.warnings.unshift(`This password is better than the most basic ones, but still not strong enough`);

        if (!strength.meetsComplexityPolicy)
            suggestions.warnings.unshift(`This password doesn't meet common complexity requirements, try including a mix of letters, numbers, and symbols`);

        listItemsHtml += suggestions.errors.map(e => `<li class="bad">${e}</li>`).join('');
        listItemsHtml += suggestions.warnings.map(w => `<li class="warn">${w}</li>`).join('');
        listItemsHtml += suggestions.information.map(i => `<li>${i}</li>`).join('');

        if (listItemsHtml.length <= 0)
            listItemsHtml = '<p class="ok">No suggestions - well done!</p>';
        else
            listItemsHtml = `<ul>${listItemsHtml}</ul>`;

        this.elements.suggestions.innerHTML = listItemsHtml;
    },


    async render(password) {
        const [worst, hibp] = await Promise.all([
            this.checkWorstPasswords(password),
            this.hibpCheck(password)
        ]);

        const strength = this.calculatePasswordStrength(password);
        const zxcvbn = this.zxcvbnCheck(password);

        const passwordLength = this.getPasswordLength(password);

        this.updateCharsetTable(strength);
        this.updateExposureList(password, worst, hibp);
        this.updateLengthVerdict(passwordLength);
        this.updateStrengthVerdict(passwordLength, strength);
        this.updateTimeToCrack(hibp, worst, passwordLength, zxcvbn);
        this.updateSuggestions(password, worst, hibp, strength, zxcvbn);

        this.renderRadarChart({ password, worst, hibp, strength, zxcvbn });
    }
};

app.init();