interface Resource {}

function openResource(): Resource {
  return {};
}

export function leaksResource(): Resource {
  return openResource();
}
