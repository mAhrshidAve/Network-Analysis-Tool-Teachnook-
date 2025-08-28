
Network Traffic Analysis Tool
=============================

Description:
------------
This tool is designed to analyze network traffic in real-time using Python. It leverages packet capture techniques, visualizes traffic data, and offers a graphical user interface for ease of use. The tool captures IP traffic and breaks down the different protocols (TCP, UDP), making it useful for monitoring network performance or detecting anomalies.

Features:
---------
- Captures live network traffic using the 'scapy' library.
- Provides protocol breakdown (TCP, UDP) with detailed statistics.
- Real-time visualization of network traffic trends using 'matplotlib'.
- Interactive graphical user interface (GUI) built with 'tkinter'.
- Saves captured data in '.pcap' format for later analysis.

Requirements:
-------------
- Python 3.x
- Required Python packages:
  - pandas
  - matplotlib
  - scapy
  - tkinter

Installation:
-------------
1. Install Python 3.x from https://www.python.org/downloads/.
2. Use the following command to install the required packages:
   '''
   pip install pandas matplotlib scapy
   '''

Usage:
------
1. Run the script by executing the following command in your terminal or command prompt:
   '''
   python network_traffic_analysis_tool.py
   '''
2. The GUI will open, allowing you to start and stop network traffic capture.
3. You can visualize real-time traffic trends and save captured data for future analysis.

Note:
-----
- Make sure you have the appropriate permissions to capture network traffic on your machine.
- Running this tool on a system without the necessary privileges may result in permission errors.

License:
--------
This tool is open-source and available for modification and redistribution under the MIT License.

