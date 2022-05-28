npm --no-git-tag-version version patch&&echo "export var version = \"$(cat package.json|jq -r .version)\";export * as wallet from \"./lib/wallet.js\";">./src/index.js && \
npm run build && \
cd web && npm i && npm run build && cd .. && \
git add package.json src/index.js web/dist && \
git commit -m "Release $(cat package.json|jq -r .version)" && \
git push && \
rm -rf web/node_modules && \
npm publish
