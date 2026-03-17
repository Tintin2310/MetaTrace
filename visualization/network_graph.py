import networkx as nx
import plotly.graph_objects as go
import pandas as pd
from src.utils.helpers import setup_logger

logger = setup_logger("network_graph")

class NetworkGraphGenerator:
    @staticmethod
    def generate_graph(metadata_df, attributions):
        """Generates a Plotly network graph from traffic metadata."""
        if metadata_df is None or metadata_df.empty:
            return None
            
        G = nx.Graph()
        
        # Add nodes and edges
        for _, row in metadata_df.iterrows():
            src = row['src_ip']
            dst = row['dst_ip']
            size = row['packet_size']
            
            # Add nodes
            if not G.has_node(src):
                G.add_node(src, type='source', label='Suspect Device')
                
            if not G.has_node(dst):
                attr = attributions.get(dst, {})
                network_type = attr.get('predicted_network', 'Unknown Network')
                G.add_node(dst, type='destination', label=network_type)
                
            # Add or update edge
            if G.has_edge(src, dst):
                G[src][dst]['weight'] += size
                G[src][dst]['interactions'] += 1
            else:
                G.add_edge(src, dst, weight=size, interactions=1)
                
        # Generate Plotly trace with better distribution
        pos = nx.spring_layout(G, k=0.5, iterations=50, seed=42)
        
        edge_x = []
        edge_y = []
        edge_hover = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color='rgba(66, 133, 244, 0.3)'),
            hoverinfo='none',
            mode='lines')
            
        node_x = []
        node_y = []
        node_text = []
        node_color = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            ntype = G.nodes[node]['type']
            label = G.nodes[node]['label']
            
            node_text.append(f"IP: {node}<br>Type: {label}")
            
            if ntype == 'source':
                node_color.append('#FF4D4D') # Critical Red
            else:
                # Use primary blue for destinations
                node_color.append('#4285F4')
                
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=[l.split('<br>')[1].replace('Type: ','') for l in node_text], # Simple label
            textposition="top center",
            marker=dict(
                showscale=False,
                colorscale='YlGnBu',
                color=node_color,
                size=15,
                line_width=2))
                
        fig = go.Figure(data=[edge_trace, node_trace],
                     layout=go.Layout(
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=0,l=0,r=0,t=0), # Remove margins for focus
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.2, 1.2]),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-1.2, 1.2]),
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)')
                     )
                     
        return fig
