import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

class TrafficVisualizer:
    @staticmethod
    def endpoint_frequency_chart(attributions):
        """Bar chart of endpoint classifications."""
        if not attributions:
            return None
            
        types = [d['predicted_network'] for d in attributions.values()]
        df = pd.DataFrame(types, columns=['Network Type'])
        counts = df['Network Type'].value_counts().reset_index()
        counts.columns = ['Network Type', 'Count']
        
        fig = px.bar(counts, x='Network Type', y='Count', 
                     color='Network Type',
                     color_discrete_sequence=['#4285F4', '#00D1FF', '#FFB703', '#FF4D4D'])
        
        fig.update_layout(
            showlegend=False,
            margin=dict(b=0,l=0,r=0,t=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(title=None, showgrid=False),
            yaxis=dict(title=None, showgrid=True, gridcolor='rgba(255,255,255,0.05)')
        )
        fig.update_traces(marker_line_color='white', marker_line_width=1, opacity=0.8)
        return fig

    @staticmethod
    def packet_size_distribution(metadata_df):
        """Histogram of packet sizes."""
        if metadata_df is None or metadata_df.empty:
            return None
            
        fig = px.histogram(metadata_df, x="packet_size", nbins=50,
                           color_discrete_sequence=['#00D1FF'])
        
        fig.update_layout(
            margin=dict(b=0,l=0,r=0,t=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(title='Packet Size (Bytes)', showgrid=False),
            yaxis=dict(title=None, showgrid=True, gridcolor='rgba(255,255,255,0.05)')
        )
        return fig
        
    @staticmethod
    def burst_timeline(bursts):
        """Timeline chart of detected bursts."""
        if not bursts:
            return None
            
        df = pd.DataFrame(bursts)
        df['burst_start'] = pd.to_datetime(df['burst_start'], format='%H:%M:%S')
        df['burst_end'] = pd.to_datetime(df['burst_end'], format='%H:%M:%S')
        
        fig = px.timeline(df, x_start="burst_start", x_end="burst_end", 
                          y="burst_intensity", color="packet_count",
                          color_continuous_scale="Viridis")
                          
        fig.update_layout(
            margin=dict(b=0,l=0,r=0,t=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(title=None, showgrid=False),
            yaxis=dict(title='Intensity', showgrid=False)
        )
        fig.update_yaxes(autorange="reversed") 
        return fig
