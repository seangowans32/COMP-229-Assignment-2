import MainRouter from './MainRouter.jsx';
import EffectsManager from './components/EffectsManager.jsx';

import './components/Global.css';
import './components/Header.css';

function App() {
  return (
    <EffectsManager>
      <MainRouter />
    </EffectsManager>
  )
}

export default App