self.onmessage = async event => {
  const logs = [];
  const safeConsole = {
    log: (...values) => {
      if (logs.length >= 1000) return;
      logs.push(values.map(value => {
        try {
          return (typeof value === 'string' ? value : JSON.stringify(value) || String(value)).slice(0, 2000);
        } catch {
          return String(value);
        }
      }).join(' '));
    }
  };

  try {
    const result = await new Function('console', `return (async () => { ${event.data}\n })()`)(safeConsole);
    const output = logs.join('\n') || (result === undefined ? 'Executed successfully.' : String(result));
    self.postMessage({ output: output.slice(0, 10000) });
  } catch (error) {
    self.postMessage({ error: String(error && error.message || error).slice(0, 10000) });
  }
};
