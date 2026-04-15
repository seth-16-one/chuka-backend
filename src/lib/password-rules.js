function normalizeIdentityTokens(values) {
  return values
    .flatMap((value) =>
      String(value || '')
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter((part) => part.length >= 3)
    )
    .filter(Boolean);
}

function buildPasswordChecklist(password, identityValues, restrictedLabel) {
  const safePassword = String(password || '');
  const lowerPassword = safePassword.toLowerCase();
  const identityTokens = normalizeIdentityTokens(identityValues);

  const rules = [
    { label: 'More than 8 characters', passed: safePassword.length > 8 },
    { label: 'Contains an uppercase letter', passed: /[A-Z]/.test(safePassword) },
    { label: 'Contains a number', passed: /\d/.test(safePassword) },
    { label: 'Contains a special character', passed: /[^A-Za-z0-9]/.test(safePassword) },
    {
      label: `Does not include your ${restrictedLabel}`,
      passed: identityTokens.every((part) => !lowerPassword.includes(part)),
    },
  ];

  const score = rules.filter((rule) => rule.passed).length;
  const isStrong = score === rules.length;

  return {
    rules,
    score,
    label: isStrong ? 'Strong' : score >= 3 ? 'Fair' : safePassword ? 'Weak' : 'Enter a password',
    tip: isStrong
      ? 'Great password strength.'
      : 'Use all the checklist rules below to create a strong password.',
    isStrong,
  };
}

module.exports = {
  buildPasswordChecklist,
};
