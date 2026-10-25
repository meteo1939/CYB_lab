// Entropia hasła: H = L * log2(R).
// R jest sumą rozmiarów klas znaków, które naprawdę występują w haśle.
// Znaki spoza ASCII (np. polskie ogonki) dodają tylko liczbę różnych takich znaków,
// żeby oszacowanie nie udawało, że „ł” pochodzi z 33-elementowego zbioru symboli.

const ASCII_SPECIAL = /[ !"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/;

export function analyzePassword(password) {
  const value = String(password ?? '');
  let hasLower = false;
  let hasUpper = false;
  let hasDigit = false;
  let hasAsciiSpecial = false;
  const extras = new Set();

  for (const ch of value) {
    if (ch >= 'a' && ch <= 'z') hasLower = true;
    else if (ch >= 'A' && ch <= 'Z') hasUpper = true;
    else if (ch >= '0' && ch <= '9') hasDigit = true;
    else if (ASCII_SPECIAL.test(ch)) hasAsciiSpecial = true;
    else extras.add(ch);
  }

  const classes = [];
  let R = 0;
  if (hasLower) {
    R += 26;
    classes.push('małe litery');
  }
  if (hasUpper) {
    R += 26;
    classes.push('wielkie litery');
  }
  if (hasDigit) {
    R += 10;
    classes.push('cyfry');
  }
  if (hasAsciiSpecial) {
    R += 33;
    classes.push('znaki specjalne');
  }
  if (extras.size) {
    R += extras.size;
    classes.push('inne znaki');
  }

  return {
    length: value.length,
    R,
    bits: R > 0 ? value.length * Math.log2(R) : 0,
    classes,
    hasLower,
    hasUpper,
    hasDigit,
    hasSpecial: hasAsciiSpecial || extras.size > 0,
  };
}

export function formatBits(bits) {
  return Number(bits || 0).toFixed(1).replace('.', ',');
}

export function strengthHint(password, policy) {
  const analysis = analyzePassword(password);
  if (!password) {
    return { ...analysis, hint: '' };
  }

  const parts = [
    `Entropia: ${formatBits(analysis.bits)} bitów.`,
    `Długość ${analysis.length}, alfabet R = ${analysis.R}${analysis.classes.length ? ` (${analysis.classes.join(', ')})` : ''}.`,
    'Wzór: H = L × log₂(R).',
  ];

  if (analysis.length < policy.minLength) {
    parts.push(`Wymagane jest co najmniej ${policy.minLength} znaków.`);
  }

  if (policy.entropyRequired) {
    if (analysis.bits < policy.minBits) {
      if (analysis.R > 1) {
        const need = Math.ceil(policy.minBits / Math.log2(analysis.R));
        parts.push(`Próg to ${policy.minBits} bitów. Przy obecnym alfabecie potrzeba co najmniej ${need} znaków.`);
      } else {
        parts.push(`Próg to ${policy.minBits} bitów.`);
      }
      const missing = [];
      if (!analysis.hasUpper) missing.push('wielką literę');
      if (!analysis.hasDigit) missing.push('cyfrę');
      if (!analysis.hasSpecial) missing.push('znak specjalny');
      if (missing.length) {
        parts.push(`Dodaj ${missing.join(', ')} — większy alfabet podnosi entropię skuteczniej niż dopisywanie takich samych znaków.`);
      }
    } else if (analysis.length >= policy.minLength) {
      parts.push(`Hasło spełnia próg ${policy.minBits} bitów.`);
    }
  } else {
    parts.push(`Polityka entropii jest wyłączona, więc próg ${policy.minBits} bitów nie jest egzekwowany.`);
  }

  return { ...analysis, hint: parts.join(' ') };
}
