import { BrowserRouter, Routes, Route } from "react-router-dom";
import DashboardPage from "./pages/Dashboard";
import UploadPage from "./pages/Upload";
import AnalysesPage from "./pages/Analyses";
import AnalysisDetailPage from "./pages/AnalysisDetail";
import ReportsPage from "./pages/Reports";
import LiveSensorPage from "./pages/LiveSensor";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/live" element={<LiveSensorPage />} />
        <Route path="/analyses" element={<AnalysesPage />} />
        <Route path="/analysis/:id" element={<AnalysisDetailPage />} />
        <Route path="/reports" element={<ReportsPage />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
