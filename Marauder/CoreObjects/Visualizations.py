import networkx as nx
import plotly.graph_objects as go
from Marauder.DataObjects.CoreDB import DatabaseConnection, OnionServices, Links, Findings, Patterns, PatternGroups

class NetworkMap:
    def __init__(self, db_path):
        self.db = DatabaseConnection(db_name=db_path)
        self.services = OnionServices(self.db)
        self.links = Links(self.db)
        self.findings = Findings(self.db)
        self.patterns = Patterns(self.db)
        self.pattern_groups = PatternGroups(self.db)

    def generate_map(self, primary_pattern_group_ids=[], secondary_pattern_group_ids=None, network_depth=1, noise_filter=True):
        # If no value is provided for secondary_pattern_group_ids, use all groups except those in primary_pattern_group_ids
        if secondary_pattern_group_ids is None:
            if primary_pattern_group_ids:
                placeholders = ','.join(['?'] * len(primary_pattern_group_ids))
                self.db.cursor.execute(
                    f"SELECT group_id FROM Pattern_Groups WHERE group_active = 1 AND group_id NOT IN ({placeholders})",
                    tuple(primary_pattern_group_ids)
                )
            else:
                self.db.cursor.execute("SELECT group_id FROM Pattern_Groups WHERE group_active = 1")
            secondary_pattern_group_ids = [row[0] for row in self.db.cursor.fetchall()]

        def get_pattern_ids(group_ids):
            ids = []
            for group_id in group_ids:
                self.db.cursor.execute(
                    "SELECT pattern_id FROM Patterns WHERE group_id = ? AND active = 1",
                    (group_id,)
                )
                ids.extend([row[0] for row in self.db.cursor.fetchall()])
            return ids

        primary_pattern_ids = get_pattern_ids(primary_pattern_group_ids)
        secondary_pattern_ids = get_pattern_ids(secondary_pattern_group_ids)
        all_pattern_ids = list(set(primary_pattern_ids + secondary_pattern_ids))

        if not primary_pattern_ids:
            print("No patterns found for the selected primary pattern groups.")
            return

        # Get all services with findings for primary patterns
        format_strings = ','.join(['?'] * len(primary_pattern_ids))
        self.db.cursor.execute(
            f"SELECT DISTINCT service_id FROM Findings WHERE pattern_id IN ({format_strings})",
            tuple(primary_pattern_ids)
        )
        primary_service_ids = set(row[0] for row in self.db.cursor.fetchall())

        if not primary_service_ids:
            print("No findings for the selected primary pattern groups.")
            return

        # Build the network of services up to the specified depth
        included_service_ids = set(primary_service_ids)
        current_layer = set(primary_service_ids)
        for depth in range(network_depth):
            next_layer = set()
            # Find all services linked to or from the current layer
            if not current_layer:
                break
            placeholders = ','.join(['?'] * len(current_layer))
            # Outgoing links
            self.db.cursor.execute(
                f"SELECT destination FROM Links WHERE origin IN ({placeholders})",
                tuple(current_layer)
            )
            next_layer.update(row[0] for row in self.db.cursor.fetchall())
            # Incoming links
            self.db.cursor.execute(
                f"SELECT origin FROM Links WHERE destination IN ({placeholders})",
                tuple(current_layer)
            )
            next_layer.update(row[0] for row in self.db.cursor.fetchall())
            # Add new layer to included services
            next_layer = next_layer - included_service_ids
            included_service_ids.update(next_layer)
            current_layer = next_layer

        if not included_service_ids:
            print("No services to display at this network depth.")
            return

        # Get onion services info
        format_strings = ','.join(['?'] * len(included_service_ids))
        self.db.cursor.execute(
            f"SELECT service_id, onion_url, inbound_links, outbound_links FROM Onion_Services WHERE service_id IN ({format_strings})",
            tuple(included_service_ids)
        )
        services = self.db.cursor.fetchall()
        service_id_to_url = {row[0]: row[1] for row in services}

        # Build graph
        G = nx.DiGraph()
        for row in services:
            G.add_node(row[1], inbound=row[2], outbound=row[3])

        # Add findings as node attribute (total findings for primary patterns)
        for sid in included_service_ids:
            pattern_format = ','.join(['?'] * len(primary_pattern_ids))
            self.db.cursor.execute(
                f"SELECT SUM(total) FROM Findings WHERE service_id = ? AND pattern_id IN ({pattern_format})",
                (sid, *primary_pattern_ids)
            )
            total_findings = self.db.cursor.fetchone()[0] or 0
            if sid in service_id_to_url:
                G.nodes[service_id_to_url[sid]]['findings'] = total_findings

        # --- NOISE FILTER: Remove nodes with 0 findings if noise_filter is True ---
        if noise_filter:
            nodes_to_remove = [n for n in G.nodes if G.nodes[n].get('findings', 0) == 0]
            G.remove_nodes_from(nodes_to_remove)

        # Add links between services (only if both nodes are in the filtered set)
        self.db.cursor.execute("SELECT origin, destination FROM Links")
        for origin, destination in self.db.cursor.fetchall():
            if origin in service_id_to_url and destination in service_id_to_url:
                if G.has_node(service_id_to_url[origin]) and G.has_node(service_id_to_url[destination]):
                    G.add_edge(service_id_to_url[origin], service_id_to_url[destination])

        # Prepare pattern strings for hover text (for all patterns)
        pattern_id_to_string = {}
        if all_pattern_ids:
            pattern_format = ','.join(['?'] * len(all_pattern_ids))
            self.db.cursor.execute(
                f"SELECT pattern_id, pattern_string FROM Patterns WHERE pattern_id IN ({pattern_format})",
                tuple(all_pattern_ids)
            )
            pattern_id_to_string = {row[0]: row[1] for row in self.db.cursor.fetchall()}

        # Visualization
        pos = nx.spring_layout(G, seed=42)
        node_x, node_y, node_size, node_color, node_text = [], [], [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_size.append(20)
            node_color.append(G.nodes[node].get('findings', 0))

            # Build detailed findings text for hover
            sid = None
            for k, v in service_id_to_url.items():
                if v == node:
                    sid = k
                    break
            findings_lines = []
            # Show primary pattern findings
            if sid:
                for pid in primary_pattern_ids:
                    self.db.cursor.execute(
                        "SELECT SUM(total) FROM Findings WHERE service_id = ? AND pattern_id = ?",
                        (sid, pid)
                    )
                    count = self.db.cursor.fetchone()[0] or 0
                    if count > 0:
                        pname = pattern_id_to_string.get(pid, f"Pattern {pid}")
                        findings_lines.append(f"<b>Primary</b> {pname}: {count}")
                # Show secondary pattern findings
                for pid in secondary_pattern_ids:
                    self.db.cursor.execute(
                        "SELECT SUM(total) FROM Findings WHERE service_id = ? AND pattern_id = ?",
                        (sid, pid)
                    )
                    count = self.db.cursor.fetchone()[0] or 0
                    if count > 0:
                        pname = pattern_id_to_string.get(pid, f"Pattern {pid}")
                        findings_lines.append(f"<b>Secondary</b> {pname}: {count}")
            findings_str = "<br>".join(findings_lines)
            node_text.append(f"{node}<br>Total Primary Findings: {G.nodes[node].get('findings', 0)}<br><br>{findings_str}")

        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x += [x0, x1, None]
            edge_y += [y0, y1, None]

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y, line=dict(width=0.5, color='black'),
            hoverinfo='none', mode='lines'
        )

        node_trace = go.Scatter(
            x=node_x, y=node_y, mode='markers', hoverinfo='text',
            marker=dict(
                showscale=True,
                # Use a high-contrast, high-visibility color scale
                colorscale='Hot',  # Alternatives: 'Hot', 'Turbo', 'Portland', 'Jet'
                size=node_size,
                color=node_color,
                colorbar=dict(
                    thickness=15,
                    title='Primary Findings',
                    xanchor='left',
                    titleside='right'
                ),
                reversescale=False
            ),
            text=node_text
        )

        fig = go.Figure(data=[edge_trace, node_trace],
                        layout=go.Layout(
                            title='Onion Service Network Map',
                            titlefont_size=16,
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=20, l=5, r=5, t=40),
                            annotations=[dict(
                                text="Filtered by Primary/Secondary Pattern Groups" if primary_pattern_group_ids or secondary_pattern_group_ids else "All Findings",
                                showarrow=False,
                                xref="paper", yref="paper",
                                x=0.005, y=-0.002
                            )],
                            xaxis=dict(showgrid=False, zeroline=False),
                            yaxis=dict(showgrid=False, zeroline=False))
                        )
        fig.show()