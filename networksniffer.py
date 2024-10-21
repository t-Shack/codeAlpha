# Import necessary modules
from fpdf import FPDF
from scapy.all import sniff, IP, TCP, Raw

# Create a list to store captured packets
captured_packets = []


# Function to determine the priority of a message
def determine_priority(message):
    # Define keywords for priority levels
    high_priority_keywords = ["error", "failure", "attack", "urgent"]
    medium_priority_keywords = ["warning", "alert", "notice"]

    # Check for high priority keywords
    for keyword in high_priority_keywords:
        if keyword in message.lower():
            return "High"

    # Check for medium priority keywords
    for keyword in medium_priority_keywords:
        if keyword in message.lower():
            return "Medium"

    # Default to low priority if no keywords are found
    return "Low"


# Define a function to process each captured packet
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if packet.haslayer(TCP):
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            packet_message = packet[Raw].load.decode('utf-8', errors='ignore') if packet.haslayer(Raw) else "No Payload"

            # Determine the priority of the packet message
            priority = determine_priority(packet_message)

            # Append packet details to the captured_packets list
            captured_packets.append([ip_src, tcp_sport, ip_dst, tcp_dport, packet_message, priority])
            print(f"IP {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport} | Message: {packet_message} | Priority: {priority}")
        else:
            captured_packets.append([ip_src, None, ip_dst, None, "No TCP Payload", "Low"])
            print(f"IP {ip_src} -> {ip_dst} | Message: No TCP Payload | Priority: Low")


# Define a function to save captured packets to a PDF
def save_packets_to_pdf(filename):
    # Create a PDF object
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Set font for the PDF
    pdf.set_font("Arial", size=12)

    # Add a title
    pdf.cell(200, 10, txt="Captured Network Packets", ln=True, align='C')
    pdf.ln(10)  # Add a line break

    # Add table headers
    pdf.cell(30, 10, txt="Source IP", border=1, align='C')
    pdf.cell(30, 10, txt="Source Port", border=1, align='C')
    pdf.cell(30, 10, txt="Destination IP", border=1, align='C')
    pdf.cell(30, 10, txt="Destination Port", border=1, align='C')
    pdf.cell(50, 10, txt="Message", border=1, align='C')
    pdf.cell(20, 10, txt="Priority", border=1, align='C')
    pdf.ln()

    # Add data rows to the table
    for packet in captured_packets:
        ip_src, tcp_sport, ip_dst, tcp_dport, packet_message, priority = packet
        pdf.cell(30, 10, txt=str(ip_src), border=1, align='C')
        pdf.cell(30, 10, txt=str(tcp_sport) if tcp_sport else "", border=1, align='C')
        pdf.cell(30, 10, txt=str(ip_dst), border=1, align='C')
        pdf.cell(30, 10, txt=str(tcp_dport) if tcp_dport else "", border=1, align='C')
        pdf.cell(50, 10, txt=str(packet_message)[:50], border=1, align='C')  # Limiting the message to 50 characters
        pdf.cell(20, 10, txt=str(priority), border=1, align='C')
        pdf.ln()

    # Save the PDF with the provided filename
    pdf.output(filename)


# Start sniffing packets
sniff(iface=None, filter="ip", prn=packet_handler, store=False)

# Save the captured packets to a PDF file
save_packets_to_pdf("captured_packets.pdf")
