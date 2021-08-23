<script type="application/vnd.starboard.nb">
# %% [markdown]

# Introduction

Welcome to the interactive documentation for the `ioc-finder` package!

Most of the documentation below is interactive to help you learn by experimenting with the package yourself.

> Tip: Press the ▶ Play button on the left (or hit `Shift` + `Enter`) to run a cell's code.

# %% [markdown]
Run the snippet below to install ioc-finder (it may take 20-30 seconds to install):
# %% [python]
import micropip
micropip.install('ioc-finder')
# %% [markdown]
Now that we've installed the ioc-finder package, we can use it:
# %% [python]
from ioc_finder import find_iocs
text = "Test foobar.com https://example.org/test/bingo.php"
iocs = find_iocs(text)
iocs['domains']
# %% [markdown]
Does that output make sense? What do you expect from the following code block?
# %% [python]
iocs['urls']
# %% [markdown]
# API

## ioc_finder.find_iocs()

This function...

# %% [python]
iocs['urls']
</script>
