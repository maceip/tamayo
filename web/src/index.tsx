/* @refresh reload */
import { render } from 'solid-js/web';
import App from './App';
import { watchFreshness } from './lib/freshness';
import './styles/site.css';

watchFreshness();

const root = document.getElementById('root');
if (!root) throw new Error('#root missing');
render(() => <App />, root);
