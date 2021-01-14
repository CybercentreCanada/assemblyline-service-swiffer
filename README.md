# Swiffer Service

This Assemblyline service uses the Python pyswf library to extract metadata and perform anomaly detection on 'audiovisual/flash' files.

**NOTE**: This service does not require you to buy any licence and is preinstalled and working after a default installation

## Execution

Swiffer will report the following information on each file when present:

#### MetaData Extraction

SWF Header:
- Version
- FileLength
- FrameSize
- FrameRate
- FrameCount

Symbol Summary:
- Main Timeline
- TagIds
- Names
