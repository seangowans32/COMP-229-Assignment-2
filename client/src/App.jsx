import MainRouter from './MainRouter.jsx';
import EffectsManager from './components-old/EffectsManager.jsx';

import './components-old/Global.css';
import './components-old/Header.css';

function App() {
  return (
    <EffectsManager>
      <MainRouter />
    </EffectsManager>
  )
}

export default App