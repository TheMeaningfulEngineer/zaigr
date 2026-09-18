## CLI Features

The UX is in a workable form at the moment.
For the time being I'm not planning any big conceptual changes there.
The only improvements that came to mind so far were:

* add a cpu/ram dependency for a setup (k3s can get OOMed if VM too small)
* specify setup dependencies in the project


## Shared filesystem ownership

Support the following ownership behavior for shared files and directories:

| Created by in VM | Owner inside VM | Owner on host |
|---|---|---|
| Root | Root | Host user |
| Normal user | Normal user | Host user |
| Service user | Service user | Host user |


## Optimisations

### Faster boot

This is where I see the most work happening.
There is a lot of moving parts and the VM start is slower than I'd like.
I'd like to explore getting rid of dependencies and taking just a subset of what zaigr needs.
The  release already builds its own kernel and has a stripped systemd install, but feel like exploring if it can go faster.


### Packaging

The base vm and the setups are built into the binary.
This results in a big binary and doesn't allow for a shared repo of usefull setups. I've opted for this case mostly for install convenience, but am open to a more modular approach users start showing up.


## Security

### Openshitch

The firewall inside the VM is currently the thing preventing the model from accessing the domains it shouldn't. I'd like to move that somehow on the host without imposing every zaigr change to be done with sudo.


### Pet test with models without safety

The current models stop if I ask them to try and break the isolation.
This makes sense because that's a definition of an attack, but for a tool that is to provide an isolated runtime for a model, this is core testing. I'd like to see if I can somehow get a model to act maliciously within a zaigr project to test the limits of the isolation.

