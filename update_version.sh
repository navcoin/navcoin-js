npm --no-git-tag-version version patch&&echo "export var version = \"$(cat package.json|jq -r .version)\";export * as wallet from \"./lib/wallet.js\";">./src/index.js && \
git add package.json src/index.js && \
git commit -m "Release $(cat package.json|jq -r .version)" && \
git push origin HEAD:main && \
npm run build && \
npm publish
