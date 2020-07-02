import matplotlib.pyplot as plt
import networkx as nx
import csv
import time
from threading import Thread

G = nx.DiGraph()


data_folder = "C:\\Users\\jensn\\OneDrive\\Master_Thesis\\Implementation\\sawtooth\\attestation_management\\client_simulation\\"

file_to_open = data_folder + "Graph.csv"


with open(file_to_open) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            G.add_edge(row['Verifier'], row['Prover'], weight=0.7)

eall = [(u, v) for (u, v, d) in G.edges(data=True)]
#elarge = [(u, v) for (u, v, d) in G.edges(data=True) if d['weight'] > 0.5]
#esmall = [(u, v) for (u, v, d) in G.edges(data=True) if d['weight'] <= 0.5]
plt.clf()

pos = nx.spring_layout(G)  # positions for all nodes

# nodes
nx.draw_networkx_nodes(G, pos, node_size=700)

# edges
nx.draw_networkx_edges(G, pos, edgelist=eall,
                    width=3, arrowstyle='->')
#nx.draw_networkx_edges(G, pos, edgelist=elarge,
#                       width=6)
#nx.draw_networkx_edges(G, pos, edgelist=esmall,
#                       width=6, alpha=0.5, edge_color='b', style='dashed')

# labels
nx.draw_networkx_labels(G, pos, font_size=10, font_family='sans-serif')

plt.axis('off')
#plt.ion()
#plt.clf()
plt.pause(1)
plt.show()

'''
def update():
    while True:
        with open(file_to_open) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                G.add_edge(row['Verifier'], row['Prover'], weight=0.7)
        eall = [(u, v) for (u, v, d) in G.edges(data=True)]
        pos = nx.spring_layout(G)  # positions for all nodes
        G.update(eall)
        print("updated")
        time.sleep(5)
'''