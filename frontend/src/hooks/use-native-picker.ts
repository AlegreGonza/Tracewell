import { useEffect, useState } from 'react'

const findPicker = () => window.pywebview?.api?.pick_file ?? null

/** Diálogo nativo de pywebview para elegir un archivo: autoriza solo el archivo elegido. */
export function useNativePicker() {
  const [picker, setPicker] = useState(findPicker)
  useEffect(() => {
    const sync = () => setPicker(() => findPicker()) // () => f: guardar la función, no llamarla
    window.addEventListener('pywebviewready', sync)
    return () => window.removeEventListener('pywebviewready', sync)
  }, [])
  return picker
}
