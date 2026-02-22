import { useRef, useEffect } from "react";
import type { NetworkNode, ContainerInfo, MapInstance } from "../types";
import { createMapInstance } from "../hooks/use-d3-map";

interface MapCanvasProps {
  showContainers: boolean;
  searchTerm: string;
  selectedNode: NetworkNode | null;
  onSelectNode: (node: NetworkNode, container?: ContainerInfo) => void;
  onClearSelection: () => void;
  onHover: (event: MouseEvent, node: NetworkNode) => void;
  onMoveHover: (event: MouseEvent) => void;
  onLeaveHover: () => void;
  instanceRef: React.MutableRefObject<MapInstance | null>;
}

export function MapCanvas({
  showContainers,
  searchTerm,
  selectedNode,
  onSelectNode,
  onClearSelection,
  onHover,
  onMoveHover,
  onLeaveHover,
  instanceRef,
}: MapCanvasProps) {
  const svgRef = useRef<SVGSVGElement>(null);

  // Create D3 instance on mount
  useEffect(() => {
    if (!svgRef.current) return;

    const instance = createMapInstance(svgRef.current, {
      onSelectNode,
      onHoverNode: onHover,
      onMoveHover,
      onLeaveNode: onLeaveHover,
      onBackgroundClick: onClearSelection,
    });

    instanceRef.current = instance;

    return () => {
      instance.destroy();
      instanceRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Mount once — callbacks are stable refs

  // Sync showContainers
  useEffect(() => {
    instanceRef.current?.setShowContainers(showContainers);
  }, [showContainers, instanceRef]);

  // Sync search
  useEffect(() => {
    instanceRef.current?.search(searchTerm);
  }, [searchTerm, instanceRef]);

  // Sync selection highlight
  useEffect(() => {
    if (selectedNode) {
      instanceRef.current?.highlightNode(selectedNode.id);
    } else {
      instanceRef.current?.clearSelection();
    }
  }, [selectedNode, instanceRef]);

  return (
    <div className="nm-map-container">
      <svg ref={svgRef} />
    </div>
  );
}
