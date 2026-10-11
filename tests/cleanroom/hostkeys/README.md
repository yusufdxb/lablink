Synthetic host keys for the clean-room test robot (tests/cleanroom/robot.Dockerfile).
They protect nothing: they exist only in disposable containers on private Docker
networks. They are fixed because the GUI-only clean-room steps click fixed
coordinates and the wrapping of the displayed fingerprints moves the dialogs:
keys generated at image build time made the layout differ from run to run.
